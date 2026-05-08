# CTF: DNS Exfiltration

**Category:** Network Forensics  
**Platform:** CyberHero Playground  
**Tools:** Wireshark, Python  

---

## Challenge Description

A `.pcap` capture file is provided containing mixed network traffic. The goal is to identify suspicious DNS queries, extract hidden data fragments, reconstruct and decode them to recover the flag.

---

## Tools Used

- **Wireshark** — packet capture analysis and DNS query filtering
- **Python 3** — Base64 decoding of the reconstructed payload

---

## Background: DNS Exfiltration

DNS exfiltration is a technique where an attacker encodes and hides data inside DNS query names. Since DNS traffic is rarely blocked by firewalls and often goes uninspected, it is commonly used to covertly exfiltrate data from a compromised network.

In this challenge, the data is split into small fragments, each embedded as a subdomain in a DNS query like:

```
<fragment>.<index>.system-update.internal
```

The index (in hex) controls the order in which fragments must be reassembled.

---

## Methodology

### Step 1 — Open the capture and identify suspicious traffic

Open `dump.pcap` in Wireshark. The traffic contains DNS queries to many legitimate-looking domains (google.com, github.com, slack.com, etc.) mixed with suspicious queries to a non-existent internal domain.

Apply the following display filter to isolate the suspicious queries:

```
dns.qry.name contains "system-update"
```

This reveals 19 DNS queries to `*.system-update.internal` that stand out from the rest of the traffic.

### Step 2 — Extract the fragments

Each query follows the pattern `<data>.<index>.system-update.internal`. The full list of extracted queries:

| Index (hex) | Fragment |
|-------------|----------|
| 00 | U0N |
| 01 | De3 |
| 02 | ByM |
| 03 | G1w |
| 04 | dF8 |
| 05 | zbm |
| 06 | dpb |
| 07 | jMz |
| 08 | cjF |
| 09 | uZ1 |
| 0a | 8xN |
| 0b | V9u |
| 0c | MHR |
| 0d | fZm |
| 0e | 9yM |
| 0f | 241 |
| 10 | MWM |
| 11 | 1fQ |
| 12 | == |

### Step 3 — Sort and reconstruct

Sort the fragments by their hex index (00 → 12) and concatenate them to form a single Base64-encoded string:

```
U0NDe3ByMG1wdF8zbmdpbjMjF8uZ18xNV9uMHRfZm05yM241MWM1fQ==
```

The `==` padding at the end is a clear indicator of Base64 encoding.

### Step 4 — Decode the payload

Decode the Base64 string using Python:

```python
import base64
base64.b64decode("U0NDe3ByMG1wdF8zbmdpbjMjF8uZ18xNV9uMHRfZm05yM241MWM1fQ==").decode()
```

**Output:**

```
SCC{pr0mpt_f0r_midni3ht_r1d_55_un0tr_f0r2411c1}
```

---

## Flag

```
SCC{pr0mpt_f0r_midni3ht_r1d_55_un0tr_f0r2411c1}
```

---

## Key Wireshark Filters Used

| Filter | Purpose |
|--------|---------|
| `dns` | Show all DNS traffic |
| `dns.qry.name contains "system-update"` | Isolate suspicious exfiltration queries |
| `dns.flags.response == 0` | Show only queries, not responses |

---

## Lessons Learned

- DNS is often an overlooked protocol from a security perspective — traffic that looks legitimate can conceal data exfiltration.
- Fragmented data in subdomains is a classic DNS tunneling pattern — short 3‑character chunks avoid length limits and blend in with normal traffic.
- The hex index in subdomains controls the reassembly order — always check the ordering field before decoding.
- Base64 padding (==) is a strong indicator of encoded data.
- Detection strategy: monitor high volumes of queries to non‑existent internal domains, or unusual entropy in subdomains.
