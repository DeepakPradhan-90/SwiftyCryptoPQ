# SwiftyCryptoPQ

A Swift wrapper that implements the FIPS 203 and FIPS 204 post-quantum algorithms, alongside
classical primitives, over well-reviewed C reference implementations.

> **Not a validated cryptographic module.** This package implements the algorithms specified
> in FIPS 203 and FIPS 204, and its conformance is tested against NIST's ACVP vectors, but it
> has not been through CMVP validation and is therefore not FIPS 140-3 validated. If you have
> a regulatory requirement for a validated module, this will not satisfy it. The code has also
> not had an independent security audit.

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

Version tags ship a precompiled XCFramework. Add the package and the `CryptoPQ` product:

```swift
dependencies: [
    .package(url: "https://github.com/DeepakPradhan-90/SwiftyCryptoPQ.git", from: "1.0.0")
]
```

```swift
.product(name: "CryptoPQ", package: "SwiftyCryptoPQ")
```

Each merge to `main` publishes the next patch release. The tag's `Package.swift` is a binary target, and the XCFramework zip is attached to the GitHub release. It contains iOS, iOS Simulator, and macOS slices.

To build from source instead, depend on the `main` branch:

```swift
.package(url: "https://github.com/DeepakPradhan-90/SwiftyCryptoPQ.git", branch: "main")
```

## Contributing

`main` accepts changes only through pull requests. A pull request runs the macOS tests and the iOS build, and a Cursor review agent comments on the diff with those check results. Merge it from GitHub after you have read the review. Merging publishes the next XCFramework release.

---

## Usage

There are two layers. The **typed key API** under `PQ` is what you should normally use: it
returns shared secrets as CryptoKit `SymmetricKey` values, validates keys on decode, and keeps
private keys in self-clearing storage. The **primitive layer** underneath (`MLKEM`, `MLDSA`,
`XWingX25519`, `HybridKEM1024`) works in `[UInt8]` and exposes derandomized entry points for
known-answer testing.

### Typed key API

```swift
import CryptoPQ

// Recipient generates a key pair. Available families are PQ.MLKEM768,
// PQ.MLKEM1024, PQ.XWing, and PQ.HybridMLKEM1024X25519.
let privateKey = try PQ.XWing.PrivateKey()
let publicKey = privateKey.publicKey            // .rawRepresentation is safe to publish

// Sender encapsulates. The secret is a CryptoKit SymmetricKey, ready for
// HKDF or AES.GCM without any byte shuffling.
let sealed = try publicKey.encapsulateSharedSecret()
let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: sealed.sharedSecret, outputByteCount: 32)

// Recipient recovers the same secret from the ciphertext.
let recovered = try privateKey.decapsulate(sealed.ciphertext)
assert(sealed.sharedSecret == recovered)

// Persist the private key without holding a copy yourself.
try privateKey.withUnsafeRawRepresentation { bytes in
    try storeInKeychain(bytes)                  // 32 bytes for PQ.XWing
}
```

Decoding a public key runs the FIPS 203 §7.2 modulus check, and decoding a private key runs
the §7.3 hash check, so malformed keys are rejected at the boundary rather than used.

### Choosing an API for your deployment target

The key types are identical on every supported version. Only the CryptoKit protocol
conformance is version-gated, because the protocols themselves did not exist until iOS 17:

| API | Available from |
| --- | --- |
| `PQ.*.PrivateKey` / `PublicKey`, `encapsulateSharedSecret()`, `decapsulate(_:)` | iOS 15 / macOS 11 |
| `KEMPublicKey` & `KEMPrivateKey` conformance, `encapsulate()`, `Encapsulation.kemResult` | iOS 17 / macOS 14 |
| Apple's own `CryptoKit.MLKEM768` etc., at which point this package is optional | iOS 26 / macOS 26 |

If your floor is below iOS 17, use `encapsulateSharedSecret()` everywhere: it is available on
all versions, including 17 and later, so you need no availability checks at all. Reach for the
protocol conformance only when you want to write code generic over CryptoKit's KEM
abstraction.

A KEM gives you a shared secret, not a cipher, so both examples below run the secret through
HKDF and encrypt with AES-GCM. Both are the [tested
code](Tests/CryptoPQUsageTests/DocumentedUsageTests.swift) rather than a sketch.

The README snippets are backed by `Tests/CryptoPQUsageTests`, so the documentation is
compiled and run in CI.

The same flow is also an iOS app at [Examples/CryptoPQDemo](Examples/CryptoPQDemo). It
encrypts and decrypts a message with AES-GCM or ChaCha20-Poly1305, using ML-KEM-768,
ML-KEM-1024, or X-Wing for the shared secret, and ML-DSA-65 to sign the ciphertext.
Open it in Xcode and run it on a simulator:

```sh
open Examples/CryptoPQDemo/CryptoPQDemo.xcodeproj
```

### Below iOS 17 — end-to-end with AES-GCM

```swift
import CryptoPQ
import CryptoKit

// Bind the KDF to your protocol and version so keys derived by different
// features can never collide.
let info = Data("MyApp/messaging/v1".utf8)

// --- Recipient, once: generate and publish a key ---
let recipientKey = try PQ.XWing.PrivateKey()
let publishedKey = recipientKey.publicKey.rawRepresentation   // 1216 bytes, not secret

// --- Sender: encapsulate, derive, encrypt ---
let publicKey = try PQ.XWing.PublicKey(rawRepresentation: publishedKey)
let encapsulation = try publicKey.encapsulateSharedSecret()

let aesKey = HKDF<SHA256>.deriveKey(
    inputKeyMaterial: encapsulation.sharedSecret,   // already a SymmetricKey
    info: info,
    outputByteCount: 32
)
let box = try AES.GCM.seal(plaintext, using: aesKey)

// Send both: the KEM ciphertext carries the shared secret, the box the message.
let kemCiphertext = encapsulation.ciphertext        // 1120 bytes for X-Wing
let sealedBox = box.combined!

// --- Recipient: decapsulate, derive the same key, decrypt ---
let sharedSecret = try recipientKey.decapsulate(kemCiphertext)
let openingKey = HKDF<SHA256>.deriveKey(
    inputKeyMaterial: sharedSecret,
    info: info,
    outputByteCount: 32
)
let recovered = try AES.GCM.open(AES.GCM.SealedBox(combined: sealedBox), using: openingKey)
```

Encapsulate once per message. The shared secret is fresh every call, so the derived AES key is
too, which is what keeps GCM's nonce reuse requirement out of your hands.

### iOS 17+ — generic over CryptoKit's KEM protocols

With an iOS 17 floor you can write against `KEMPublicKey` and `KEMPrivateKey` and never name a
concrete algorithm, which keeps the choice of family a one-line change:

```swift
import CryptoPQ
import CryptoKit

let info = Data("MyApp/messaging/v1".utf8)

func seal<K: KEMPublicKey>(_ plaintext: Data, to publicKey: K) throws -> (kem: Data, box: Data) {
    let result = try publicKey.encapsulate()        // KEM.EncapsulationResult
    let aesKey = HKDF<SHA256>.deriveKey(
        inputKeyMaterial: result.sharedSecret,
        info: info,
        outputByteCount: 32
    )
    let box = try AES.GCM.seal(plaintext, using: aesKey)
    return (result.encapsulated, box.combined!)
}

func open<K: KEMPrivateKey>(kem: Data, box: Data, with privateKey: K) throws -> Data {
    let sharedSecret = try privateKey.decapsulate(kem)
    let aesKey = HKDF<SHA256>.deriveKey(
        inputKeyMaterial: sharedSecret,
        info: info,
        outputByteCount: 32
    )
    return try AES.GCM.open(AES.GCM.SealedBox(combined: box), using: aesKey)
}

// Swapping families, or moving to Apple's implementation later, touches one line:
let recipientKey = try PQ.XWing.PrivateKey()
let message = try seal(plaintext, to: recipientKey.publicKey)
let recovered = try open(kem: message.kem, box: message.box, with: recipientKey)
```

Those same two functions accept CryptoKit's native `MLKEM768` and `XWingMLKEM768X25519` keys
unchanged on iOS 26+, which the test suite verifies.

If your floor is below iOS 17 but you still want the generic form, gate it and fall back to
`encapsulateSharedSecret()`:

```swift
if #available(iOS 17.0, macOS 14.0, *) {
    return try seal(plaintext, to: recipientKey.publicKey)
} else {
    return try sealUsingSharedSecret(plaintext, to: recipientKey.publicKey)
}
```

### Migrating to Apple's implementation later

The names under `PQ` mirror CryptoKit's `MLKEM768`, `MLKEM1024`, and `XWingMLKEM768X25519`,
which arrive in iOS 26, and the encodings are the same standards. The test suite confirms that
ML-KEM-768 ciphertexts cross between this package and CryptoKit's native implementation in
both directions, and that a message sealed with `PQ.XWing` opens under
`CryptoKit.XWingMLKEM768X25519`. So keys already stored on device stay valid, mixed-version
deployments interoperate, and raising your target is largely a matter of dropping the `PQ.`
prefix.

The one exception is ML-DSA: Apple exposes it only inside the Secure Enclave, so the `MLDSA`
API here remains useful even on iOS 26.

---

## Primitive layer

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
---

## Handling of secret material

Secrets are cleared at three levels.

**In the C code.** Upstream PQClean never scrubs its stack buffers, so seeds, secret
polynomial vectors, decrypted messages, and derived shared secrets stay resident after every
call, and the Keccak sponge state is freed without being cleared. The vendored sources are
patched to zero those locals as they die; see [patches/README.md](patches/README.md) for the
exact sites and for how to re-apply the patch after a PQClean update.

**In the Swift code.** Hybrid combiners absorb their inputs incrementally rather than
concatenating shared secrets into one buffer, and X25519 shared secrets are read directly out
of CryptoKit's self-zeroing `SharedSecret` storage via
`X25519.withSharedSecret(privateKey:peerPublicKey:_:)`. Remaining intermediates are wiped
through `memset_s` routed so the optimizer cannot discard it.

**In the typed API.** Shared secrets are returned as CryptoKit `SymmetricKey`, whose storage
is locked and zeroed on deallocation, so the secret is never handed to you as an array you
have to remember to wipe. Private keys live in a reference-counted box that clears itself when
the last copy goes away, and `withUnsafeRawRepresentation` scopes access to a closure rather
than vending a copy.

**In your process.** `ProcessHardening.disableCoreDumps()` prevents a crash from writing key
material to disk, and `lockMemory`/`unlockMemory` pin long-lived keys out of swap. Both are
opt-in; call them during startup, before any keys exist.

### Threat model

These measures defend against *post-hoc* memory disclosure: core dumps, crash reports, swap
files, and reused heap pages. They do **not** defend against an attacker with live access to
the running process or a debugger on a jailbroken device.

Residual exposure you should know about:

- Wiping a Swift `[UInt8]` is best effort. `withUnsafeMutableBytes` requires a uniquely
  referenced buffer, so if the array shares storage, copy-on-write hands back a fresh buffer
  and the wipe scrubs the copy while the original survives. The primitive layer returns
  secrets as `[UInt8]`, handing the caller a copy this package cannot reach; the typed `PQ`
  API avoids this and is the safer default.
- Even in the typed API, PQClean writes the shared secret into a caller-supplied buffer, so
  one short-lived array exists between the C call and the `SymmetricKey`. It is wiped
  immediately, but it does exist.
- The compiler may still spill intermediate values to registers or stack slots that no
  `memset` can reach, and iOS memory compression is outside application control.
- None of this substitutes for hardware-backed keys. Prefer storing the 32-byte X-Wing seed in
  the Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, or wrapped under a Secure
  Enclave key, and keep session keys ephemeral.

---

## License

SwiftyCryptoPQ is licensed under the [Apache License 2.0](LICENSE).

The vendored ML-KEM, ML-DSA, Keccak, and SHA-2 implementations come from
[PQClean](https://github.com/PQClean/PQClean) and are public domain, and the bundled test
vectors come from NIST ACVP and the X-Wing draft. See [NOTICE](NOTICE) for full attribution.
