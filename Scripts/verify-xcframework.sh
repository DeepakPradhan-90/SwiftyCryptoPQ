#!/bin/bash
# Links a throwaway package against an already-built CryptoPQ.xcframework and
# runs real operations through it.
#
# Building the XCFramework proves it compiles; this proves the binary works.
# The C implementation is linked in and the Swift interface no longer mentions
# it, so a packaging mistake would otherwise only surface for a consumer.
set -euo pipefail

SOURCE="${1:?usage: verify-xcframework.sh <path to CryptoPQ.xcframework>}"
SOURCE="$(cd "$(dirname "$SOURCE")" && pwd)/$(basename "$SOURCE")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A local binary target's path has to be relative to the package root.
cp -R "$SOURCE" "$WORK/CryptoPQ.xcframework"
mkdir -p "$WORK/Sources/Verify"

cat >"$WORK/Package.swift" <<'EOF'
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Verify",
    platforms: [.macOS(.v11)],
    targets: [
        .executableTarget(name: "Verify", dependencies: ["CryptoPQ"]),
        .binaryTarget(name: "CryptoPQ", path: "CryptoPQ.xcframework")
    ]
)
EOF

cat >"$WORK/Sources/Verify/main.swift" <<'EOF'
import CryptoKit
import CryptoPQ
import Foundation

func check(_ condition: Bool, _ message: String) {
    if !condition {
        print("FAIL: \(message)")
        exit(1)
    }
}

// Every KEM family round-trips through the typed API.
let mlkem768 = try PQ.MLKEM768.PrivateKey()
var sealed = try mlkem768.publicKey.encapsulateSharedSecret()
check(try mlkem768.decapsulate(sealed.ciphertext) == sealed.sharedSecret, "ML-KEM-768")

let mlkem1024 = try PQ.MLKEM1024.PrivateKey()
sealed = try mlkem1024.publicKey.encapsulateSharedSecret()
check(try mlkem1024.decapsulate(sealed.ciphertext) == sealed.sharedSecret, "ML-KEM-1024")

let xwing = try PQ.XWing.PrivateKey()
sealed = try xwing.publicKey.encapsulateSharedSecret()
check(try xwing.decapsulate(sealed.ciphertext) == sealed.sharedSecret, "X-Wing")

let hybrid = try PQ.HybridMLKEM1024X25519.PrivateKey()
sealed = try hybrid.publicKey.encapsulateSharedSecret()
check(try hybrid.decapsulate(sealed.ciphertext) == sealed.sharedSecret, "HybridMLKEM1024X25519")

// A derived key encrypts and decrypts, which exercises the vendored SHA-3.
let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: sealed.sharedSecret, outputByteCount: 32)
let message = Data("xcframework verification".utf8)
let box = try AES.GCM.seal(message, using: key)
check(try AES.GCM.open(box, using: key) == message, "AES-GCM round trip")

// ML-DSA signs and verifies, and rejects a tampered message.
let signer = try MLDSA.generateKeyPair(mode: .dsa65)
let signature = try MLDSA.sign(message: Array(message), privateKey: signer.privateKey, mode: .dsa65)
check(
    try MLDSA.verify(message: Array(message), signature: signature, publicKey: signer.publicKey, mode: .dsa65),
    "ML-DSA-65 accepts a valid signature"
)
check(
    try !MLDSA.verify(message: Array(Data("tampered".utf8)), signature: signature, publicKey: signer.publicKey, mode: .dsa65),
    "ML-DSA-65 rejects a tampered message"
)

print("CryptoPQ.xcframework verified")
EOF

swift run --package-path "$WORK" Verify
