# SwiftyCryptoPQ

A Swift wrapper around optimized, FIPS-compliant post-quantum and classical cryptographic primitives, leveraging the robust C implementations under the hood.

## Features

- **ML-DSA (FIPS 204)**: Standardized post-quantum digital signature algorithm (Dilithium). Supports:
  - `ML-DSA-44`
  - `ML-DSA-65` (Recommended default)
  - `ML-DSA-87`
- **ML-KEM (FIPS 203)**: Standardized post-quantum key encapsulation mechanism (Kyber). Supports:
  - `ML-KEM-768`
  - `ML-KEM-1024`
- **X25519 (RFC 7748)**: Classical Curve25519 Diffie-Hellman key agreement via `CryptoKit`.
- **X-Wing (draft-connolly-cfrg-xwing-kem-10)**: Hybrid post-quantum/classical KEM combining `ML-KEM-768` and `X25519`.
- **HybridKEM1024**: A non-standard hybrid KEM combining `ML-KEM-1024` and `X25519` with a `SHA-512` combiner. See [Non-standard constructions](#non-standard-constructions).

---

## Platform support

Requires **iOS 15+ / macOS 11+**. Nothing in the source uses API newer than iOS 13, but
current Xcode releases refuse deployment targets below iOS 15, so that is the real floor.

The point of this package is that ML-KEM and ML-DSA are available well below the iOS 26
requirement of Apple's own CryptoKit implementations: the lattice primitives are vendored
[PQClean](https://github.com/PQClean/PQClean) C, and only `X25519` and `SHA-512` come from
`CryptoKit`.

---

## Installation

Add SwiftyCryptoPQ to your `Package.swift` dependencies:

```swift
dependencies: [
    .package(url: "https://github.com/DeepakPradhan-90/SwiftyCryptoPQ.git", from: "1.0.0")
]
```

Then add `CryptoPQ` to your target dependencies:

```swift
targets: [
    .target(
        name: "MyTarget",
        dependencies: [
            .product(name: "CryptoPQ", package: "SwiftyCryptoPQ")
        ]
    )
]
```

---

## Usage

### 1. ML-DSA (Digital Signatures)

Generate keypairs, sign messages, and verify signatures with ML-DSA-44, 65, or 87.

```swift
import CryptoPQ

// 1. Generate a keypair (defaults to .dsa65)
let keyPair = try MLDSA.generateKeyPair(mode: .dsa65)

// 2. Sign a message
let message = [UInt8]("Hello, CryptoPQ!".utf8)
let signature = try MLDSA.sign(message: message, privateKey: keyPair.privateKey)

// 3. Verify the signature (automatically infers mode from public key length)
let isValid = try MLDSA.verify(message: message, signature: signature, publicKey: keyPair.publicKey)
print("Signature is valid: \(isValid)") // true
```

---

### 2. ML-KEM (Key Encapsulation)

Establish secure shared secrets with ML-KEM-768 or ML-KEM-1024.

```swift
import CryptoPQ

// 1. Generate keypair for recipient
let receiverKeyPair = try MLKEM.generateKeyPair(mode: .kem768)

// 2. Sender encapsulates a shared secret using the recipient's public key
let (senderSecret, ciphertext) = try MLKEM.encapsulate(publicKey: receiverKeyPair.publicKey)

// 3. Recipient decapsulates the shared secret using their private key
let receiverSecret = try MLKEM.decapsulate(ciphertext: ciphertext, privateKey: receiverKeyPair.privateKey)

assert(senderSecret == receiverSecret, "Shared secrets must match!")
```

---

### 3. X-Wing Hybrid KEM

Use the state-of-the-art hybrid KEM combining post-quantum (`ML-KEM-768`) and classical (`X25519`) algorithms for maximum resilience.

The decapsulation key is a 32-byte seed, and the encapsulation key, ciphertext, and shared
secret are 1216, 1120, and 32 bytes respectively, as specified in draft-10.

```swift
import CryptoPQ

// 1. Generate a hybrid keypair (privateKey is a 32-byte seed)
let receiverKeyPair = try XWingX25519.generateKeyPair()

// 2. Sender encapsulates a shared secret
let (senderSecret, ciphertext) = try XWingX25519.encapsulate(publicKey: receiverKeyPair.publicKey)

// 3. Recipient decapsulates the shared secret
let receiverSecret = try XWingX25519.decapsulate(ciphertext: ciphertext, privateKey: receiverKeyPair.privateKey)

assert(senderSecret == receiverSecret, "Hybrid secrets must match!")
```

---

### 4. HybridKEM1024

A **non-standard** hybrid KEM combining `ML-KEM-1024` (post-quantum Security Category 5) and classical `X25519` key agreement, hashing the inputs using `SHA-512` to produce a 512-bit shared secret. Prefer X-Wing unless you specifically need Category 5 and control both ends of the wire.

```swift
import CryptoPQ

// 1. Generate an ultra-high-security hybrid keypair
let receiverKeyPair = try HybridKEM1024.generateKeyPair()

// 2. Sender encapsulates a 512-bit shared secret
let (senderSecret, ciphertext) = try HybridKEM1024.encapsulate(publicKey: receiverKeyPair.publicKey)

// 3. Recipient decapsulates the shared secret
let receiverSecret = try HybridKEM1024.decapsulate(ciphertext: ciphertext, privateKey: receiverKeyPair.privateKey)

assert(senderSecret == receiverSecret, "Hybrid secrets must match!")
```

---

### 5. X25519 Key Agreement

Standard classical Diffie-Hellman key agreement.

```swift
import CryptoPQ

// 1. Alice and Bob generate keypairs
let aliceKeys = try X25519.generateKeyPair()
let bobKeys = try X25519.generateKeyPair()

// 2. Alice computes shared secret using Bob's public key
let aliceSecret = try X25519.keyExchange(privateKey: aliceKeys.privateKey, peerPublicKey: bobKeys.publicKey)

// 3. Bob computes shared secret using Alice's public key
let bobSecret = try X25519.keyExchange(privateKey: bobKeys.privateKey, peerPublicKey: aliceKeys.publicKey)

assert(aliceSecret == bobSecret, "Shared secrets must match!")
```

---

## Architecture

The project splits functionality into two clean targets:
1. **`CryptoPQC`**: A low-level C target wrapping raw PQClean implementations for the post-quantum primitives (fips202, sha2, ml-dsa, ml-kem).
2. **`CryptoPQ`**: A high-level, idiomatic Swift target wrapping `CryptoPQC` and integrating `CryptoKit` for X25519 and SHA3-256 hybrid operations.

---

## Standards Alignment

- **FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)
- **FIPS 204**: Module-Lattice-Based Digital Signature Standard (ML-DSA)
- **RFC 7748**: Elliptic Curves for Security (X25519)
- **draft-connolly-cfrg-xwing-kem-10**: X-Wing Hybrid Key Encapsulation Mechanism

Conformance is tested against published vectors rather than round-trips alone:

| Construction | Vectors |
| --- | --- |
| ML-KEM-768/1024 keyGen, encaps, decaps, key checks | NIST ACVP (FIPS 203) |
| ML-DSA-44/65/87 signature verification | NIST ACVP (FIPS 204) |
| X-Wing keygen, encaps, decaps | draft-connolly-cfrg-xwing-kem-10, Appendix C |

Both FIPS 203 input validation checks are enforced: the §7.2 modulus check on encapsulation
keys and the §7.3 hash check on decapsulation keys. PQClean performs neither on its own.

ML-DSA signing and verification accept the FIPS 204 `context` string, which defaults to empty.

---

## Non-standard constructions

`HybridKEM1024` is a construction of this package's own design. It has no specification, no
external analysis, and will not interoperate with anything else. It is kept for callers who
control both endpoints and want an ML-KEM-1024 hybrid; everyone else should use X-Wing.

## Known limitations

- X25519 comes from `CryptoKit`, which throws when a key agreement produces the all-zero
  shared secret. X-Wing does not require that check, so a peer deliberately sending a
  low-order `ct_X` causes an error here rather than a distinct shared secret.
- Secret material held in `[UInt8]` is wiped with `memset_s` once it is no longer needed, but
  Swift may have made copies before then. This is not a substitute for the Secure Enclave.

---

## License

SwiftyCryptoPQ is licensed under the [Apache License 2.0](LICENSE).

The vendored ML-KEM, ML-DSA, Keccak, and SHA-2 implementations come from
[PQClean](https://github.com/PQClean/PQClean) and are public domain, and the bundled test
vectors come from NIST ACVP and the X-Wing draft. See [NOTICE](NOTICE) for full attribution.
