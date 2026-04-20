# b01lers CTF 2026

## Egg

In this challenge, the flag was passed as an argument to a uvicorn/starlette based HTTP server. Author added some deliberate baits for LLMs which worked quite well. 

### Solution

The app used 4 uvicorn workers. For each egg created, it wrote a specific template to a python file, then zipped it. Main template code was -

```py
def gen_ascii_art(self, offset: int) -> None:
    if not all(c.isascii() and c.isalnum() for c in "{filename}"):
        return None
    f = open("{filename}", "r")
    f.seek(offset)
    self.art = f.read(40)
```
the problem was, we couldnt specify any filename to bypass the alnum check unless filename was an array. But it was impossible cuz the filename was explicitly passed through str function - 

`filename = str(data["filename"])`

First, I noticed that we are given the secret key used to sign the cookie, meaning we could mess around with our session stored data. Player ID was random, but the `SESSION_TIMESTAMP` was directly used to buid the path for the file the above template was written to. 

```py
time_diff = time.time() - player_creation_time
self.id = sha256(str(time_diff * random.random()).encode()).hexdigest()

dir_path = Path(EGG_DIR) / self.id
egg = dir_path / "creature.py"
```

If we set player creation time to NaN, anything multiplied will return nan. so the self.id effectively becomes sha256("nan") for each egg. This means every egg will write to same path. 

Next, I searched how we can take advantage of this. 

```py
fd = open(egg, "w")

egg_template = EGG_TEMPLATE.format(
    name=name,
    ...,
    filename=filename,
)

fd.write(egg_template)
fd.close()
```

If two parallel workers hit this section around same time, we can get a case where both create an fd to `<sha256(nan)/creature.py`. 

Although everything happens very fast, but in an ideal case, we can hit something like this - 

1. Worker A opens the file. File resets since `w` tag is set. 
2. Worker B opens the file. File contents again become empty.

Its important that both workers open the file before any start writing.

3. Worker A starts writing a longer template, say 100 bytes. Worker B also starts writing just behind worker A say 80 bytes. Everything Worker B is meant to write will overwrite what worker A wrote. But since its 20 bytes shorter, last 20 bytes will be what worker A wrote. 

This is how it will look in practice - 

```py
    def gen_ascii_art(self, offset: int) -> None:
        if not all(c.isascii() and c.isalnum() for c in "asciiart"):
            return None
        f = open("asciiart", "r")
        f.seek(offset)
        self.art = f.read(40) # worker B ends here
        f = open("/proc/1/cmdline", "r")
        f.seek(offset)
        self.art = f.read(40)
```

Worker A has the filename `/proc/1/cmdline`, and has a longer name, specifically 95 bytes longer than worker B.

Worker B will almost fully overwrite what worker A wrote, except the carefully adjusted leftover 3 lines. Now the isalnum check if for the name written by worker B, but the worker A filename isn't checked. And it will be given to use during hatching!!

That's it for the exploit. I used GCP on same server to make the script run reliably, and it still took a LOT of reruns to get the flag since the ideal window is just too small.