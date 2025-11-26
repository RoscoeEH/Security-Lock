# KeyCrypt
KeyCrypt is a client-server model that protection mechanism for secure servers. The server is hosted on a secure keypad that connects to a sensor to detect breaches, in the event of a breach the clients running on each server initiate a shutdown to take advantage of at rest disk encryption for protection. 

Each client verifies that the server is in place by sending out constant, randomly generated, challenge messages that the server signs with HMAC-SHA2-256 and returns to the client. The protocol agrees on an initial session key using ML-KEM768 and and HKDF, it refreshes the session key every 2^24 messages. At rest the ML-KEM private key is protected with xChaCha20Poly1305 using an Argon2 password based key. The client runs as a daemon and starts immediately on power-up. By refreshing session keys with HKDF, redistribution of public keys should never have to happen in the lifetime of the device.


## Protocol Description
When the keypad powers up, it requires the user to enter a PIN. This PIN is used to decrypt the ML-KEM decapsulation key. Once unlocked, the keypad initializes and waits for incoming client connections.

When a client connects, it generates a shared secret for the session and encapsulates it using ML-KEM768. The client then sends the keypad three items:

1. the encapsulated shared secret
2. a 256-bit random challenge
3. a 128-bit salt

The keypad decapsulates the shared secret, and both the client and keypad feed the shared secret and salt into an HKDF to derive the session key.

Next, the keypad signs the client's challenge and returns the signed challenge. The client verifies the signature and then sends a second message containing:

1. a 32-bit message counter
2. a new 256-bit random challenge

The keypad signs the counter, challenge, and a status code and returns the signed result for verification. This challenge-response process continues for the duration of the session unless the keypad detects a breach or is disarmed.

If a breach is detected, the keypad immediately ceases all communication with clients. Clients treat the loss of communication as a security event and initiate a lockdown on each server. Any protocol error, such as an invalid signature, also triggers a lockdown.

When the message counter reaches 2^24, the server and client refresh the session key by deriving a new key through HKDF using a newly generated salt. The counter is then reset to 0. In practice, the session key is expected to be refreshed approximately every 13 to 14 weeks.
