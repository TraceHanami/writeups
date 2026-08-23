# Writeup: ihate-daa

- **Challenge Name:** ihate-daa
- **Category:** Web / Algorithms / Scripting
- **Challenge URL:** `https://ihate-daa-57f215eb8649.chals.z0d1ak.org`

---

## Challenge Overview

The challenge presents a web application with the heading **"Which way did the flag go?"** and prompts the user to select one of several path links (e.g. `/?path=cvhgfhyvkvq`, `/?path=0ij436dr`, etc.).

Navigating to each link presents either:
1. Another set of child path links (branch nodes).
2. A dead-end page (`"nope :( - Try a different route."`).
3. The flag page when the correct path is reached.

The state space forms a directed graph / tree with multiple levels and branches.

---

## Analysis & Solution Strategy

Since the structure represents a state graph (reminiscent of Design and Analysis of Algorithms - DAA graph traversal problems), the goal is to perform a fast, concurrent graph search (Breadth-First Search or Depth-First Search) over the endpoints until reaching the target node containing the flag.

### Crawler Implementation

We implemented a multithreaded BFS crawler using Python's `requests` and `concurrent.futures.ThreadPoolExecutor` to handle high request concurrency:

```python
import requests
import re
import concurrent.futures
import sys

BASE = "https://ihate-daa-57f215eb8649.chals.z0d1ak.org"
session = requests.Session()

visited = set(["/"])
frontier = ["/"]

for depth in range(1, 100):
    print(f"Depth {depth}: {len(frontier)} nodes to visit (total visited: {len(visited)})")
    next_frontier = []
    
    def get_url(p):
        url = BASE + p if p.startswith("/") else BASE + "/" + p
        try:
            r = session.get(url, timeout=10)
            return p, r.text
        except Exception as e:
            return p, ""

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(get_url, frontier)
        for p, text in results:
            if not text:
                continue
            if "zdk{" in text or "flag{" in text or "CTF{" in text:
                print(f"\n[!] FLAG FOUND at {p}:")
                print(text)
                sys.exit(0)
            links = re.findall(r'href=["\'](/\?path=[^"\']+)["\']', text)
            for l in links:
                if l not in visited:
                    visited.add(l)
                    next_frontier.append(l)
    
    if not next_frontier:
        print("Graph exhausted, no more paths.")
        break
    frontier = next_frontier
```

---

## Execution & Results

At **Depth 11**, having traversed the graph up to path `/?path=uxhqkhii`, the crawler retrieved the following response:

```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Flag Found</title>
  <style>
    :root { color-scheme: dark; }
    body { font-family: monospace; max-width: 860px; margin: 40px auto; padding: 0 16px; }
    a { color: #ff5a5a; }
    .card { border: 1px solid #444; border-radius: 10px; padding: 16px; }
    .muted { opacity: 0.8; }
  </style>
</head>
<body>
  <div class="card">
    <h1>flag:</h1><p><strong>zdk{i_1OVE_graPH_traVeRS4L_and_DYnaMic_INsTanceS}</strong></p>
  </div>
</body>
</html>
```

---

## Flag

```text
zdk{i_1OVE_graPH_traVeRS4L_and_DYnaMic_INsTanceS}
```
