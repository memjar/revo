---
name: protocol-re
description: Reverse engineer binary network protocols — packet structure, state machines, field identification, replay attacks.
metadata:
  version: "1"
---

# Protocol RE

Reverse engineer unknown or undocumented binary network protocols from packet captures, client binaries, or live traffic interception.

## When to use

Use when you encounter an unknown binary protocol over TCP/UDP and need to determine: message framing, field layout, handshake sequences, authentication mechanisms, or state machine transitions.

## Capture setup

tcpdump (raw):

```bash
tcpdump -i en0 -w capture.pcap host TARGET_IP and port TARGET_PORT
```

tshark (filtered):

```bash
tshark -i en0 -f "tcp port 8080" -w capture.pcap
tshark -r capture.pcap -T fields -e data.data | xxd -r -p
```

mitmproxy (TLS intercept):

```bash
mitmproxy --mode transparent --showhost -w dump.mitm
```

## Framing analysis

Identify message boundaries first. Common patterns:

| Pattern                 | Indicator                                                        |
| ----------------------- | ---------------------------------------------------------------- |
| Length-prefixed         | First 2-4 bytes = message length (check both LE/BE)              |
| Delimiter-based         | Fixed byte sequence between messages (0x0d0a, 0x00)              |
| Fixed-size              | All messages same length                                         |
| TLV (Type-Length-Value) | Repeating tag+length+data triplets                               |
| Magic header            | Constant bytes at start of every message (identify version/type) |

Quick length-prefix test:

```python
import struct
data = open("msg.bin", "rb").read()
le16 = struct.unpack_from("<H", data, 0)[0]
be16 = struct.unpack_from(">H", data, 0)[0]
le32 = struct.unpack_from("<I", data, 0)[0]
be32 = struct.unpack_from(">I", data, 0)[0]
for label, val in [("LE16", le16), ("BE16", be16), ("LE32", le32), ("BE32", be32)]:
    if val == len(data) or val == len(data) - 2 or val == len(data) - 4:
        print(f"{label} = {val} matches payload length")
```

## Field identification

Strategies for identifying field semantics:

1. **Entropy analysis** — high entropy regions = encrypted/compressed; low = flags/enums
2. **Differential analysis** — send same request with one param changed, diff the bytes
3. **Timestamp detection** — look for Unix epoch (4/8 bytes), check if value falls in plausible range
4. **String detection** — scan for UTF-8/ASCII runs; null-terminated vs length-prefixed
5. **Counter detection** — incrementing values across sequential messages = sequence numbers
6. **Checksum detection** — last 2-4 bytes; CRC32, Adler32, or simple XOR/sum

## State machine extraction

Track message type transitions to build the protocol FSM:

```python
from collections import defaultdict
transitions = defaultdict(set)
prev_type = None
for msg in messages:
    msg_type = msg[OFFSET:OFFSET+SIZE]
    if prev_type is not None:
        transitions[prev_type].add(msg_type)
    prev_type = msg_type
```

Common protocol phases:

1. Handshake / version negotiation
2. Authentication / key exchange
3. Session setup
4. Request-response or streaming data
5. Keepalive / heartbeat
6. Teardown / close

## Replay and mutation

Replay a captured message:

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.sendall(captured_bytes)
response = s.recv(4096)
```

Mutation testing — flip bits/fields systematically to find:

- Which fields are validated (server rejects)
- Which fields are ignored (server accepts any value)
- Authentication tokens (server rejects on change)
- Sequence numbers (server rejects out-of-order)

## Protobuf detection

Many modern protocols use Protocol Buffers. Indicators:

- Varint encoding (MSB continuation bit pattern)
- Field numbers encoded as `(field_number << 3) | wire_type`
- Wire types: 0=varint, 1=64-bit, 2=length-delimited, 5=32-bit

Decode attempt:

```bash
protoc --decode_raw < message.bin
```

If that produces structured output, it's likely protobuf. Map field numbers to semantics via differential analysis.

## Documentation template

```
Protocol: [name]
Transport: TCP/UDP port [N]
Endianness: LE/BE
Framing: [length-prefix/delimiter/fixed]
Auth: [mechanism]

Message Types:
  0x01 - Handshake request
  0x02 - Handshake response
  ...

State Machine:
  INIT -> HANDSHAKE -> AUTH -> READY -> [REQUEST <-> RESPONSE] -> CLOSE
```
