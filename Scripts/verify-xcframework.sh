#!/bin/bash
# Links a throwaway package against an already-built CryptoPQ.xcframework,
# compiles it for every slice the framework ships, and runs real operations
# through the macOS one.
#
# Building the XCFramework proves it compiles; this proves the binary is
# usable. The C implementation is linked in and the Swift interface no longer
# mentions it, so a packaging mistake would otherwise only surface for a
# consumer. The exercises live in a library target rather than the executable
# so that the iOS slices, which cannot be run here, are still type-checked
# against their own swiftinterface.
set -euo pipefail

SOURCE="${1:?usage: verify-xcframework.sh <path to CryptoPQ.xcframework>}"
SOURCE="$(cd "$(dirname "$SOURCE")" && pwd)/$(basename "$SOURCE")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A local binary target's path has to be relative to the package root.
cp -R "$SOURCE" "$WORK/CryptoPQ.xcframework"
mkdir -p "$WORK/Sources/Verify" "$WORK/Sources/VerifyRun"

cat >"$WORK/Package.swift" <<'EOF'
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Verify",
    platforms: [.iOS(.v15), .macOS(.v11)],
    products: [
        .library(name: "Verify", targets: ["Verify"])
    ],
    targets: [
        .target(name: "Verify", dependencies: ["CryptoPQ"]),
        .executableTarget(name: "VerifyRun", dependencies: ["Verify"]),
        .binaryTarget(name: "CryptoPQ", path: "CryptoPQ.xcframework")
    ]
)
EOF

cat >"$WORK/Sources/Verify/Verify.swift" <<'EOF'
import CryptoKit
import CryptoPQ
import Foundation

private func check(_ condition: Bool, _ message: String) {
    if !condition {
        print("FAIL: \(message)")
        exit(1)
    }
}

public func verifyCryptoPQ() throws {
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
}
EOF

cat >"$WORK/Sources/VerifyRun/main.swift" <<'EOF'
import Verify

try verifyCryptoPQ()
print("operations succeeded")
EOF

echo "== Running operations against the macOS slice"
swift run --package-path "$WORK" VerifyRun

# A slice that is missing, or present but unusable because it carries a
# swiftinterface from the wrong platform, only shows up when something is
# compiled against it. Both cases fail the build here.
#
# xcodebuild logs "Supported platforms for the buildables in the current
# scheme is empty" for a package library target. It is noise, not a failure.
for destination in 'generic/platform=iOS' 'generic/platform=iOS Simulator'; do
  echo "== Compiling against ${destination}"
  (cd "$WORK" && xcodebuild -scheme Verify \
    -destination "$destination" \
    -derivedDataPath "$WORK/dd" \
    -quiet \
    CODE_SIGNING_ALLOWED=NO \
    build)
done

echo "CryptoPQ.xcframework verified"
