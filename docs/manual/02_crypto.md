[[PART:Part II — Cryptography Foundations|Hashing, digital signatures, key management and encryption, explained from first principles]]

# Hashing and SHA-256

## Bits, bytes and hexadecimal

Everything in a computer, including every file, is a sequence of **bits** (0 or 1). Eight bits make a **byte**, which can hold a value from 0 to 255. Long binary values are hard to read, so we write them in **hexadecimal** (base 16), using the digits `0-9` and `a-f`. One hex digit represents exactly 4 bits, so one byte is two hex digits.

```
binary   1111 1111   =  decimal 255  =  hex ff
binary   0010 1100   =  decimal 44   =  hex 2c
256 bits  =  32 bytes  =  64 hex digits
```

This is why a SHA-256 hash always looks like 64 characters of `0-9a-f`.

## What is a hash function?

A **cryptographic hash function** takes an input of any size and produces a fixed-size output called a **hash** or **digest**. You can think of it as a fingerprint for data: small, unique in practice, and impossible to reverse.

```
SHA-256("hello")   = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
SHA-256("hello.")  = a completely different 64-character value
SHA-256(4 GB file) = still exactly 64 hex characters
```

## The five properties that make hashing useful

| Property | Meaning | Why FileVow needs it |
|---|---|---|
| Deterministic | The same input always produces the same hash | An unchanged file re-hashes to exactly the stored value |
| Fixed output size | Always 256 bits, whatever the input size | Easy to store, index and compare |
| Avalanche effect | Changing a single input bit flips about half (around 128) of the output bits | Even a one-character edit produces an obviously different hash |
| Pre-image resistance (one-way) | Given a hash, you cannot find an input that produces it | The hash reveals nothing about the file content |
| Collision resistance | It is infeasible to find two different inputs with the same hash | An attacker cannot craft a malicious file that matches the original's hash |

> KEY IDEA: Collision resistance is the property that makes integrity checking trustworthy. If an attacker could produce a different file with the same hash, the whole system would be fooled. This is exactly why **MD5 and SHA-1 must not be used**: practical collisions have been demonstrated for both (MD5 in 2004, SHA-1 in 2017 with the "SHAttered" attack).

## How SHA-256 works internally

You will never implement SHA-256 yourself (Python's `hashlib` does it in optimised C), but understanding the process explains several design decisions.

### Step 1: Padding

The message is extended so that its length becomes a multiple of 512 bits. A single `1` bit is appended, then as many `0` bits as needed, and finally the original message length as a 64-bit number. Including the length prevents certain attacks where messages of different lengths could collide.

### Step 2: Splitting into blocks

The padded message is divided into **512-bit (64-byte) blocks**. A 1 MB file becomes 16,384 blocks.

### Step 3: Initial state

SHA-256 keeps an internal **state of eight 32-bit words** (`a` to `h`, 256 bits in total). They start at fixed constants: the first 32 bits of the fractional parts of the square roots of the first eight prime numbers (2, 3, 5, 7, 11, 13, 17, 19). Using "nothing up my sleeve" numbers like these shows that the designers did not hide a backdoor in the constants.

### Step 4: Message schedule

Each 512-bit block is split into sixteen 32-bit words. These are expanded to **64 words** using bit rotations, shifts and XOR operations, so that every input bit influences many words.

### Step 5: Compression (64 rounds)

For each of the 64 words, one **round** mixes the word into the state using:

- **Rotations** (bits shifted around in a circle),
- **XOR** (exclusive or), **AND** and **NOT** logic functions called *Ch* (choose) and *Maj* (majority),
- **Addition modulo 2^32**,
- A round constant `K[t]` (from the cube roots of the first 64 primes).

After 64 rounds the result is added to the state from before the block was processed.

### Step 6: Chaining and output

The state after one block is the starting state for the next block. This **chaining** is why changing one byte anywhere in a file changes the final hash completely: the difference ripples through every following block. After the last block, the eight state words joined together are the 256-bit hash.

## Why the project hashes files in chunks

Because SHA-256 processes data block by block, you can feed it the file a piece at a time with `update()` and the result is identical to hashing the whole file at once. Reading in 64 KB chunks means a 10 GB file is hashed using only 64 KB of memory.

```python
import hashlib

CHUNK = 64 * 1024

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:          # "rb" = read raw bytes, no text conversion
        while block := f.read(CHUNK):
            h.update(block)
    return h.hexdigest()                  # 64 hex characters
```

> WARNING: Always open files in binary mode (`"rb"`). Text mode converts line endings on Windows (`\r\n` to `\n`), which would give a different hash from the real bytes on disk.

## How FileVow uses hashing

| Where | What is hashed | Purpose |
|---|---|---|
| Baseline | Each monitored file | The reference value |
| Verification | Each monitored file again | Comparison with the reference |
| Mirror vault | The decrypted mirror copy | Proves the mirror still matches the record |
| Content addressing | File content | The SHA-256 is the vault object's name, enabling deduplication |
| Signatures | The canonical integrity record | RSA signs this hash (Chapter 5) |
| Audit chain | Each audit entry plus the previous entry's hash | Builds the tamper-evident chain (Chapter 13) |
| Key fingerprints | The public key bytes | A short identifier for pinning keys |

## The limitation of hashing alone

Anyone can compute a SHA-256 hash. There is no secret involved. So if an attacker can write to both a file **and** the database where its reference hash is stored, they can update both and the comparison will still say "OK". Hashing proves *whether* data changed, but not *who* approved the reference value. Solving that requires a secret that the attacker does not have: a **digital signature**, covered next.

# Public-Key Cryptography and RSA Signatures

## Two families of cryptography

| | Symmetric cryptography | Asymmetric (public-key) cryptography |
|---|---|---|
| Keys | One secret key, shared by everyone who uses it | A **key pair**: a private key and a public key |
| Examples | AES, HMAC | RSA, elliptic-curve (ECDSA, Ed25519) |
| Speed | Very fast | Much slower |
| Rule | Whoever holds the key can do everything | What the private key does, only the public key can check. The private key cannot be derived from the public key |
| Used in FileVow for | Encrypting mirror copies (AES-GCM), TOTP codes (HMAC) | Signing integrity records, reports and audit checkpoints (RSA) |

### The signet ring analogy

A medieval king sealed documents with wax pressed by his **signet ring**. Only the king owned the ring (the **private key**), but everybody knew what the royal seal looked like (the **public key**). Anyone could check a seal; nobody else could make one. A digital signature works the same way, except that the "seal" is mathematically bound to the exact content of the document. Change one character and the seal no longer fits.

## What a digital signature guarantees

- **Integrity**: the signed data has not been modified since it was signed.
- **Authenticity**: it was signed by the holder of the private key.
- **Non-repudiation**: the holder cannot plausibly deny having signed it, since nobody else has the key.

## How RSA works: the mathematics with small numbers

RSA (Rivest, Shamir and Adleman, 1977) is based on modular arithmetic. `a mod n` means "the remainder after dividing `a` by `n`" (for example `17 mod 5 = 2`). The example below uses tiny numbers so you can follow every step. Real keys use the same steps with numbers hundreds of digits long.

### Key generation

```
1. Choose two secret prime numbers:       p = 61,  q = 53
2. Compute the modulus:                   n = p x q = 3233                     (public)
3. Compute Euler's totient:               phi(n) = (p-1)(q-1) = 60 x 52 = 3120 (secret)
4. Choose a public exponent e that shares no factor with phi(n):
                                          e = 17                               (public)
5. Compute the private exponent d so that (e x d) mod phi(n) = 1:
                                          d = 2753
   check: 17 x 2753 = 46801 = 15 x 3120 + 1   -> remainder 1  OK

Public key  = (n = 3233, e = 17)
Private key = (n = 3233, d = 2753)      p, q and phi(n) are destroyed or kept secret
```

### Signing

To sign a value `m` (in practice, a hash), raise it to the power of the private exponent:

```
m = 2790
signature s = m^d mod n = 2790^2753 mod 3233 = 65
```

### Verifying

Anyone with the public key raises the signature to the power `e` and compares:

```
s^e mod n = 65^17 mod 3233 = 2790     equals m  -> signature VALID
```

If an attacker changes `m` to anything else, for example 2791, then `65^17 mod 3233` is still 2790, which does not match, so the signature is **invalid**. To make a valid signature for 2791 they would need `d`.

### Why the attacker cannot compute d

Computing `d` requires `phi(n)`, which requires `p` and `q`, which requires **factoring** `n`. Factoring 3233 is instant. Factoring a 3072-bit `n` (about 925 decimal digits) is beyond every known computer and algorithm. The security of RSA rests on this single assumption: multiplying two large primes is easy, but splitting the product back into them is infeasible.

> NOTE: Large-scale quantum computers running Shor's algorithm could factor RSA moduli. None exist today that can threaten RSA-3072. Post-quantum signature schemes (such as ML-DSA, standardised by NIST in 2024) can be mentioned as future work in your project report.

## Why we sign a hash, not the file

RSA can only sign a number smaller than `n`, and RSA operations are slow. So the process is:

1. Build the data to sign (the integrity record).
2. Hash it with SHA-256, giving a small fixed-size value.
3. Sign that hash with RSA.

This combination is what "RSA with SHA-256" means. The hash makes signing fast and size-independent; RSA proves who approved it.

## Padding: why textbook RSA is insecure and what PSS fixes

The calculation above is **textbook RSA**. Used directly it has serious weaknesses:

- **Deterministic**: the same input always produces the same signature, leaking patterns.
- **Multiplicative (malleable)**: `sig(a) x sig(b) mod n = sig(a x b)`. An attacker who has two genuine signatures can combine them into a valid signature for a third value nobody signed.
- **Small or structured values** can be attacked mathematically.

Real systems apply a **padding scheme** to the hash before the RSA operation. We use **PSS (Probabilistic Signature Scheme)**, defined in PKCS #1 v2.2 (RFC 8017):

1. A random **salt** is generated for each signature.
2. The hash and salt are combined and hashed again.
3. A **mask generation function (MGF1, using SHA-256)** spreads this value over the full width of the key.
4. A fixed structure with a trailing marker byte is built, then the RSA private operation is applied.

The consequences:

- Signing the same record twice gives **different signatures**, and both verify.
- Combining signatures produces garbage, because the structure is destroyed, so forgery by multiplication fails.
- PSS has a formal security proof, which is why it is preferred over the older PKCS #1 v1.5 padding for new designs.

> KEY IDEA: The full name of our algorithm is **RSA-PSS with SHA-256 and MGF1-SHA-256, using a 3072-bit key and public exponent 65537**. Memorise it; it is what you will be asked.

## Key size

| Key size | Approximate security strength | Status |
|---|---|---|
| 1024 bits | 80 bits | Broken in practice, do not use |
| 2048 bits | 112 bits | Minimum acceptable today |
| **3072 bits** | **128 bits** | **Recommended; safe beyond 2030 (NIST SP 800-57)** |
| 4096 bits | about 140 bits | Stronger but slower; little practical benefit |

"128-bit security" means an attacker would need about 2^128 operations, which is far beyond any realistic computing power.

## What exactly is signed: the integrity record

The system does not sign only the hash. It signs a complete **integrity record**:

```json
{
  "record_id": 42,
  "file_path": "C:/inetpub/wwwroot/index.html",
  "version": 3,
  "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "file_size": 5120,
  "permissions": "rw-r--r--",
  "owner": "BUILTIN\\Administrators",
  "mirror_object_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "signing_key_id": "a1b2c3d4e5f60718",
  "signed_at": "2026-11-23T10:15:00Z"
}
```

Each field closes a specific attack:

| Field | Attack it prevents |
|---|---|
| `sha256` | Content modification |
| `file_path` | Swapping: copying the valid signed record of `a.txt` onto `b.txt` |
| `version` | Rollback: restoring an older but genuinely signed record (see Chapter 16) |
| `mirror_object_sha256` | Pointing the record at a different (malicious) mirror copy |
| `file_size`, `permissions`, `owner` | Silent metadata or permission tampering |
| `signing_key_id` | Confusion between keys during rotation; signing with an unauthorised key |
| `signed_at` | Establishes when approval happened, for audit |

## Canonical JSON: why byte-for-byte consistency matters

A signature is over **exact bytes**. These two JSON strings mean the same thing but are different bytes:

```
{"a":1,"b":2}
{ "b": 2, "a": 1 }
```

If the record were serialised differently when signing and when verifying, a genuine signature would fail. The solution is **canonical serialisation**: always sort keys, use no extra whitespace, use UTF-8, use a fixed timestamp format (ISO 8601 in UTC with a `Z` suffix), and represent paths consistently (forward slashes, normalised case on Windows).

```python
import json

def canonical(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
```

## The code: signing and verifying

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                  salt_length=padding.PSS.MAX_LENGTH)

def sign_record(private_key, record: dict) -> bytes:
    # The library hashes canonical(record) with SHA-256, applies PSS, then RSA.
    return private_key.sign(canonical(record), PSS, hashes.SHA256())

def verify_record(public_key, record: dict, signature: bytes) -> bool:
    try:
        public_key.verify(signature, canonical(record), PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False
```

A 3072-bit RSA signature is 384 bytes long. It is stored as binary (BLOB) in the database, or as base64 text in JSON exports.

## Why RSA signatures instead of HMAC

**HMAC** (hash-based message authentication code) also protects data with a secret, but it is symmetric: the same key both creates and checks the code. The always-running agent must check records constantly, so with HMAC it would also hold the key that **creates** records. Anyone who compromises the agent could then forge records.

With RSA, the agent holds only the **public key**. It can check every seal but can never produce one. Approval power stays with the human holding the private key. This separation is the main reason the project uses RSA.

## Replaying the attack with signatures in place

```
Stored:   {path, sha256: "9f86...", version: 3}  + RSA signature

Attacker edits index.html             -> live hash is now "a1c3..."
Attacker edits the database row       -> sha256: "a1c3..."
Verification: signature was made over "9f86..."   -> verify() FAILS
The attacker cannot produce a new signature: the private key is not on the server.
Result: RECORD_TAMPERED (critical)
```

# Key Management

Cryptography moves the problem of protecting data to the problem of protecting **keys**. A perfectly implemented RSA signature is worthless if the private key sits unprotected next to the database. This chapter explains how the system creates, stores, identifies, rotates and backs up its keys.

## The two-key design

The system uses two separate RSA key pairs with different jobs and different protection levels.

| | Baseline signing key | Agent key |
|---|---|---|
| Signs | File integrity records (approving a file's state) | 15-minute verification reports and audit checkpoints |
| Private key stored | PEM file encrypted with a passphrase, ideally on removable media (USB) | Windows Credential Manager via `keyring` (protected by DPAPI) |
| When unlocked | Only while an admin approves a change and types the passphrase | Always (the agent runs unattended) |
| Public key stored | Database (`signing_keys`) plus a pinned fingerprint in the config | Same |
| If stolen, the attacker can... | Forge baselines (serious, so the key is kept offline) | Forge reports and checkpoints, but **not** baselines; files remain protected |

> KEY IDEA: The key that must always be available is the one whose theft does the least harm. This is called **limiting the blast radius**, and it is the most important security decision in the project.

## Generating keys

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_keypair(passphrase: bytes | None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    enc = (serialization.BestAvailableEncryption(passphrase)
           if passphrase else serialization.NoEncryption())
    private_pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8, enc)
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return private_pem, public_pem
```

- `public_exponent=65537` is the universal standard. It is prime, large enough to avoid small-exponent attacks, and has only two `1` bits, which makes verification fast.
- **PKCS #8** is the standard container format for private keys. **PEM** is its text encoding (base64 between `-----BEGIN ...-----` lines).
- The library generates `p` and `q` using a cryptographically secure random number generator and tests them for primality.

## Protecting the baseline private key with a passphrase

`BestAvailableEncryption` encrypts the private key file. Your passphrase is passed through a deliberately slow **key derivation function**, which turns it into a 256-bit encryption key; that key then encrypts the private key with AES. Without the passphrase, the file is useless to a thief, and the slow derivation makes guessing passphrases expensive.

Passphrase rules for the project:

- At least 16 characters; a sentence of several random words works well.
- Never stored on disk, in the database, in environment variables, or in logs.
- Entered only at the moment of approval, held in memory only while signing, then discarded.

### Where the key file lives

| Option | Security | Convenience |
|---|---|---|
| USB drive plugged in only for approvals | High | Medium (recommended for the project) |
| Folder on the same machine with strict permissions | Medium | High |
| Hardware token or TPM (non-exportable key) | Very high | Lower; possible future work |

## Protecting the agent key with DPAPI

The agent must sign reports without a human present, so it cannot ask for a passphrase. Instead, the private key is stored in **Windows Credential Manager** using the `keyring` library. Credential Manager encrypts secrets with **DPAPI (Data Protection API)**, which ties the encryption to the Windows account the agent runs as. Another user account on the same machine cannot read it, and copying the stored data to another machine does not help.

```python
import keyring

keyring.set_password("FileVow", "agent_private_key", private_pem.decode())
pem = keyring.get_password("FileVow", "agent_private_key")
```

The same mechanism stores the **vault encryption key** (Chapter 7) and the **JWT signing secret** (Chapter 14).

## Key fingerprints and identifiers

A public key is several hundred bytes long. To refer to it compactly, the system computes a **fingerprint**: the SHA-256 hash of the public key's DER bytes. The first 16 hex characters are used as the `key_id`.

```python
def fingerprint(public_key) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()       # key_id = fingerprint[:16]
```

## Fingerprint pinning: defeating public-key substitution

A clever attacker might think: "I cannot forge signatures with the admin's key, so I will generate **my own** key pair, replace the public key in the database, and re-sign every record with my private key." Every signature would then verify.

The defence is **pinning**: the full fingerprint of the genuine baseline public key is written into the configuration file. When the agent loads a public key from the database, it computes the fingerprint and refuses to use any key that does not match the pinned value. A mismatch raises a critical `KEY_SUBSTITUTION_DETECTED` alert.

Additional layers:

1. The configuration file is itself a monitored file with a signed record.
2. The dashboard displays the fingerprint so an admin can compare it with a copy kept elsewhere (even printed on paper).
3. The fingerprint is also stored in Credential Manager, so the agent compares three independent copies.

## Key rotation

Keys should be replaced periodically (for example yearly) or immediately if compromise is suspected.

1. Generate a new key pair. It gets a new `key_id`.
2. Mark the old key `retired` in `signing_keys`. Retired keys can still **verify** old signatures but are never used to sign.
3. Re-sign all current records with the new key (one approval session with the passphrase).
4. Update the pinned fingerprint in the configuration.
5. Record the rotation in the audit log.

If a key is **compromised**, mark it `revoked` instead. Signatures made with a revoked key are treated as invalid, which forces a re-baseline under a fresh key after a manual review.

## Backing up keys

- Keep an encrypted backup of the baseline private key in a second safe location (another USB drive).
- If the baseline private key is lost, nothing is broken, but no new changes can be approved. You would generate a new key pair and re-baseline after verifying the current files are trustworthy.
- If the vault key is lost, the mirror copies cannot be decrypted. Back it up (exported and encrypted with a passphrase) when the system is set up.

# Symmetric Encryption and AES-256-GCM

The mirror vault stores copies of sensitive files. Those copies must be **confidential** (unreadable to anyone who steals the vault) and **tamper-evident** (any modification must be detected). AES-256-GCM provides both at once.

## What encryption does

Encryption transforms readable data (**plaintext**) into unreadable data (**ciphertext**) using a **key**. Decryption reverses it with the same key. Without the key, the ciphertext reveals nothing about the plaintext except its approximate length.

## AES: the block cipher

**AES (Advanced Encryption Standard)** was selected by NIST in 2001 after a public competition. It is a **block cipher**: it encrypts fixed blocks of 128 bits (16 bytes) at a time. AES-256 uses a 256-bit key and 14 rounds. Each round applies four operations:

| Operation | What it does | Purpose |
|---|---|---|
| SubBytes | Replaces each byte using a fixed substitution table (S-box) | Non-linearity (confusion) |
| ShiftRows | Shifts the rows of the 4x4 byte grid | Spreads bytes across columns |
| MixColumns | Mixes the four bytes of each column mathematically | Diffusion: one byte affects many |
| AddRoundKey | XORs the block with a round key derived from the main key | Brings in the secret |

There is no known practical attack on AES. Brute-forcing a 256-bit key would require 2^256 attempts, which is physically impossible. Modern CPUs have dedicated AES instructions (AES-NI), so it is also extremely fast.

## Modes of operation: why the mode matters

AES alone only encrypts one 16-byte block. A **mode of operation** defines how to encrypt longer data.

- **ECB** (encrypt each block separately) is insecure: identical plaintext blocks produce identical ciphertext blocks, revealing patterns. Never use it.
- **CBC** chains blocks together but provides no integrity; attackers can modify ciphertext in controlled ways.
- **GCM (Galois/Counter Mode)** provides encryption **and** authentication. It is the modern standard (used in TLS 1.3, for example).

## How GCM works

GCM combines two mechanisms:

1. **Counter mode (CTR) for encryption.** A 96-bit **nonce** is combined with a counter (1, 2, 3...). Each counter block is encrypted with AES to produce a keystream, which is XORed with the plaintext. This turns AES into a fast stream cipher.
2. **GHASH for authentication.** The ciphertext (and optional associated data) is processed with a polynomial hash over a mathematical structure called a Galois field, keyed by a value derived from the AES key. The result is encrypted to form a 128-bit **authentication tag**.

On decryption, GCM recomputes the tag. If **a single bit** of the ciphertext, the nonce, the tag or the associated data was changed, the tags do not match and decryption **fails with an error**. No plaintext is returned. This is called **authenticated encryption**.

```
encrypt(key, nonce, plaintext, aad)  -> ciphertext + 16-byte tag
decrypt(key, nonce, ciphertext+tag, aad) -> plaintext   or   InvalidTag error
```

## The nonce: the one rule you must never break

A **nonce** ("number used once") must **never be reused with the same key**. If two messages are encrypted with the same key and nonce, an attacker can XOR the ciphertexts to cancel the keystream and recover information about both plaintexts, and can also forge authentication tags.

The system generates a fresh random 96-bit nonce for every object with `os.urandom(12)`. With random nonces, the probability of a repeat stays negligible up to roughly 2^32 encryptions under one key, which is far beyond what a FIMS will ever perform. The nonce is not secret; it is stored in front of the ciphertext.

## Associated data (AAD): binding ciphertext to its identity

GCM can authenticate extra data that is not encrypted, called **associated data (AAD)**. The vault passes the object's SHA-256 name as AAD. This binds each ciphertext to its name: if an attacker renames or swaps vault objects (for example putting the ciphertext of an old version under the name of the current version), decryption fails because the AAD no longer matches.

## Compress, then encrypt

Encrypted data looks random and cannot be compressed. So the vault **compresses first** (with Zstandard) and then encrypts. Text files such as HTML and configuration typically shrink by 60-80%.

## The vault key

- A random 256-bit key generated once with `AESGCM.generate_key(bit_length=256)`.
- Stored in Windows Credential Manager (DPAPI), never in the database, config files or source code.
- A passphrase-protected export is created at setup for disaster recovery.

## The code

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import zstandard as zstd

def seal(plaintext: bytes, key: bytes, name: str) -> bytes:
    nonce = os.urandom(12)
    data = zstd.ZstdCompressor(level=10).compress(plaintext)
    return nonce + AESGCM(key).encrypt(nonce, data, name.encode())

def unseal(blob: bytes, key: bytes, name: str) -> bytes:
    nonce, ct = blob[:12], blob[12:]
    data = AESGCM(key).decrypt(nonce, ct, name.encode())   # raises InvalidTag if tampered
    return zstd.ZstdDecompressor().decompress(data)
```

## Summary of algorithms so far

| Algorithm | Type | Key | Output | Role in FileVow |
|---|---|---|---|---|
| SHA-256 | Hash | none | 256-bit digest | Detect content changes, name vault objects, chain audit entries |
| RSA-PSS-SHA256 | Asymmetric signature | 3072-bit key pair | 384-byte signature | Authenticate integrity records, reports and checkpoints |
| AES-256-GCM | Authenticated symmetric encryption | 256-bit secret key | Ciphertext + 128-bit tag | Protect mirror copies: confidentiality and tamper detection |
