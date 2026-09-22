import XCTest
import CryptoKit
@testable import CryptoPQ

/// Tests for the typed key API and its CryptoKit `KEM` protocol conformance.
final class KEMTypeTests: XCTestCase {

    // MARK: - Round trips through the version-independent API

    /// Exercises one family through `encapsulateSharedSecret()`/`decapsulate(_:)`,
    /// which are available on every supported OS version.
    private func assertRoundTrip<Family: _KEMFamily>(
        _ family: Family.Type,
        sharedSecretBitCount: Int,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let privateKey = try KEMPrivateKeyOf<Family>()
        let publicKey = privateKey.publicKey

        XCTAssertEqual(publicKey.rawRepresentation.count, KEMPublicKeyOf<Family>.byteCount, file: file, line: line)

        let encapsulation = try publicKey.encapsulateSharedSecret()
        XCTAssertEqual(encapsulation.ciphertext.count, Family._ciphertextByteCount, file: file, line: line)
        XCTAssertEqual(encapsulation.sharedSecret.bitCount, sharedSecretBitCount, file: file, line: line)

        let recovered = try privateKey.decapsulate(encapsulation.ciphertext)
        XCTAssertEqual(encapsulation.sharedSecret, recovered, file: file, line: line)

        // A second encapsulation must produce a different secret.
        let other = try publicKey.encapsulateSharedSecret()
        XCTAssertNotEqual(encapsulation.sharedSecret, other.sharedSecret, file: file, line: line)
    }

    func testMLKEM768RoundTrip() throws {
        try assertRoundTrip(PQ.MLKEM768.self, sharedSecretBitCount: 256)
    }

    func testMLKEM1024RoundTrip() throws {
        try assertRoundTrip(PQ.MLKEM1024.self, sharedSecretBitCount: 256)
    }

    func testXWingRoundTrip() throws {
        try assertRoundTrip(PQ.XWing.self, sharedSecretBitCount: 256)
        XCTAssertEqual(PQ.XWing.PrivateKey.byteCount, 32, "the draft defines the decapsulation key as a seed")
    }

    func testHybridMLKEM1024X25519RoundTrip() throws {
        try assertRoundTrip(PQ.HybridMLKEM1024X25519.self, sharedSecretBitCount: 512)
    }

    // MARK: - Encoding

    private func assertEncodingRoundTrips<Family: _KEMFamily>(
        _ family: Family.Type,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let privateKey = try KEMPrivateKeyOf<Family>()

        // Restoring from the encoded private key recovers the same public key.
        let encoded = privateKey.withUnsafeRawRepresentation { Data($0) }
        XCTAssertEqual(encoded.count, KEMPrivateKeyOf<Family>.byteCount, file: file, line: line)

        let restored = try KEMPrivateKeyOf<Family>(rawRepresentation: encoded)
        XCTAssertEqual(restored.publicKey, privateKey.publicKey, file: file, line: line)

        // A secret encapsulated to the original key decapsulates with the restored one.
        let encapsulation = try privateKey.publicKey.encapsulateSharedSecret()
        XCTAssertEqual(
            try restored.decapsulate(encapsulation.ciphertext),
            encapsulation.sharedSecret,
            file: file, line: line
        )

        // Public keys round-trip through their encoding.
        let publicKey = try KEMPublicKeyOf<Family>(rawRepresentation: privateKey.publicKey.rawRepresentation)
        XCTAssertEqual(publicKey, privateKey.publicKey, file: file, line: line)
    }

    func testEncodingRoundTrips() throws {
        try assertEncodingRoundTrips(PQ.MLKEM768.self)
        try assertEncodingRoundTrips(PQ.MLKEM1024.self)
        try assertEncodingRoundTrips(PQ.XWing.self)
        try assertEncodingRoundTrips(PQ.HybridMLKEM1024X25519.self)
    }

    func testRejectsMalformedKeys() throws {
        let privateKey = try PQ.MLKEM768.PrivateKey()
        let goodPublicKey = privateKey.publicKey.rawRepresentation

        // Wrong length.
        XCTAssertThrowsError(try PQ.MLKEM768.PublicKey(rawRepresentation: goodPublicKey.dropLast())) { error in
            XCTAssertEqual(error as? KEMError, .invalidKeyLength)
        }
        XCTAssertThrowsError(try PQ.MLKEM768.PrivateKey(rawRepresentation: Data([1, 2, 3]))) { error in
            XCTAssertEqual(error as? KEMError, .invalidKeyLength)
        }

        // The FIPS 203 modulus check runs at decode time: 0xFFF exceeds q in
        // both coefficients packed into the first three bytes.
        var unreduced = Array(goodPublicKey)
        unreduced[0] = 0xFF
        unreduced[1] = 0xFF
        unreduced[2] = 0xFF
        XCTAssertThrowsError(try PQ.MLKEM768.PublicKey(rawRepresentation: Data(unreduced))) { error in
            XCTAssertEqual(error as? MLKEMError, .malformedPublicKey)
        }

        // Corrupting the embedded H(ek) fails the FIPS 203 hash check.
        var tamperedPrivateKey = privateKey.withUnsafeRawRepresentation { Array($0) }
        let hashOffset = 384 * 3 + MLKEM.Mode.kem768.publicKeyLength
        tamperedPrivateKey[hashOffset] ^= 0x01
        XCTAssertThrowsError(try PQ.MLKEM768.PrivateKey(rawRepresentation: Data(tamperedPrivateKey))) { error in
            XCTAssertEqual(error as? MLKEMError, .malformedPrivateKey)
        }

        // Ciphertexts of the wrong length are rejected before decapsulation.
        let encapsulation = try privateKey.publicKey.encapsulateSharedSecret()
        XCTAssertThrowsError(try privateKey.decapsulate(encapsulation.ciphertext.dropLast())) { error in
            XCTAssertEqual(error as? KEMError, .invalidCiphertextLength)
        }
    }

    // MARK: - Agreement with the primitive layer

    func testTypedAPIAgreesWithPrimitiveLayer() throws {
        // A known X-Wing seed must produce the same public key and shared secret
        // through both layers.
        let seed = [UInt8](repeating: 0x5A, count: 32)
        let primitive = try XWingX25519.generateKeyPair(seed: seed)
        let typed = try PQ.XWing.PrivateKey(rawRepresentation: Data(seed))

        XCTAssertEqual(Array(typed.publicKey.rawRepresentation), primitive.publicKey)

        let (primitiveSecret, ciphertext) = try XWingX25519.encapsulate(publicKey: primitive.publicKey)
        let typedSecret = try typed.decapsulate(Data(ciphertext))
        XCTAssertEqual(typedSecret, SymmetricKey(data: primitiveSecret))
    }

    // MARK: - CryptoKit KEM protocol conformance

    /// Round-trips through CryptoKit's protocols only, with no reference to any
    /// concrete type, proving the conformance is usable by generic code written
    /// against CryptoKit rather than against this package.
    @available(iOS 17.0, macOS 14.0, tvOS 17.0, watchOS 10.0, *)
    private func assertConformsToCryptoKitKEM<K: KEMPrivateKey>(
        _ type: K.Type,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let privateKey = try K.generate()
        let result: KEM.EncapsulationResult = try privateKey.publicKey.encapsulate()
        let recovered = try privateKey.decapsulate(result.encapsulated)
        XCTAssertEqual(result.sharedSecret, recovered, file: file, line: line)
    }

    func testCryptoKitKEMConformance() throws {
        guard #available(iOS 17.0, macOS 14.0, tvOS 17.0, watchOS 10.0, *) else {
            throw XCTSkip("CryptoKit's KEM protocols require iOS 17 / macOS 14")
        }
        try assertConformsToCryptoKitKEM(PQ.MLKEM768.PrivateKey.self)
        try assertConformsToCryptoKitKEM(PQ.MLKEM1024.PrivateKey.self)
        try assertConformsToCryptoKitKEM(PQ.XWing.PrivateKey.self)
        try assertConformsToCryptoKitKEM(PQ.HybridMLKEM1024X25519.PrivateKey.self)
    }

    func testEncapsulationConvertsToCryptoKitResult() throws {
        guard #available(iOS 17.0, macOS 14.0, tvOS 17.0, watchOS 10.0, *) else {
            throw XCTSkip("CryptoKit's KEM protocols require iOS 17 / macOS 14")
        }
        let privateKey = try PQ.XWing.PrivateKey()
        let encapsulation = try privateKey.publicKey.encapsulateSharedSecret()
        let converted = encapsulation.kemResult

        XCTAssertEqual(converted.sharedSecret, encapsulation.sharedSecret)
        XCTAssertEqual(converted.encapsulated, encapsulation.ciphertext)
    }

    // MARK: - Interoperability with CryptoKit's native implementations

    /// Where the OS ships its own implementation of the same standard, keys and
    /// ciphertexts must cross between it and this package.
    func testInteroperatesWithNativeCryptoKitMLKEM768() throws {
        guard #available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, *) else {
            throw XCTSkip("CryptoKit's native MLKEM768 requires iOS 26 / macOS 26")
        }

        // Native key, our encapsulation, native decapsulation.
        let nativePrivateKey = try CryptoKit.MLKEM768.PrivateKey()
        let ours = try PQ.MLKEM768.PublicKey(rawRepresentation: nativePrivateKey.publicKey.rawRepresentation)
        let encapsulation = try ours.encapsulateSharedSecret()
        XCTAssertEqual(
            try nativePrivateKey.decapsulate(encapsulation.ciphertext),
            encapsulation.sharedSecret,
            "our ciphertext must decapsulate under CryptoKit's implementation"
        )

        // Our key, native encapsulation, our decapsulation.
        let ourPrivateKey = try PQ.MLKEM768.PrivateKey()
        let nativePublicKey = try CryptoKit.MLKEM768.PublicKey(
            rawRepresentation: ourPrivateKey.publicKey.rawRepresentation
        )
        let nativeResult = try nativePublicKey.encapsulate()
        XCTAssertEqual(
            try ourPrivateKey.decapsulate(nativeResult.encapsulated),
            nativeResult.sharedSecret,
            "CryptoKit's ciphertext must decapsulate under ours"
        )
    }
}
