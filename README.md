# Security Lock

## Message Structure
Challenge:
```
Magic (3 bytes) | message number (4 bytes) | message (32 bytes)
```
magic = "CHG"

Response:
```
Magic (3 bytes) | message number (4 bytes) | message (32 bytes) | signature (32 bytes)
```
magic = "RSP"

## Generate key
```
openssl rand -out <key file> 32
```
