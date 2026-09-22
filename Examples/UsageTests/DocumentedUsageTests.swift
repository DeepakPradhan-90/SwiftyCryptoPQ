import XCTest
import CryptoKit
import CryptoPQ

/// The exact code printed in the README, so the documentation cannot drift away
/// from a compiling, passing implementation.
///
/// Imports `CryptoPQ` normally rather than `@testable`, so these tests only
/// touch API a real caller can reach.
final class DocumentedUsageTests: XCTestCase {

    /// Domain separation string for the KDF. Bind it to your protocol and
    /// version so keys derived by different features can never collide.
    private static let info = Data("SwiftyCryptoPQ/example/v1".utf8)

    /// What travels over the wire: the KEM ciphertext that lets the recipient
    /// recover the shared secret, plus the AES-GCM box.
    private struct Message {
        let kemCiphertext: Data
        let sealedBox: Data
    }

    // MARK: - Works on every supported version (iOS 15+)

    private func sealUniversal(_ plaintext: Data, to publicKeyBytes: Data) throws -> Message {
        let publicKey = try PQ.XWing.PublicKey(rawRepresentation: publicKeyBytes)

        // Encapsulate: one fresh shared secret plus the ciphertext carrying it.
        let encapsulation = try publicKey.encapsulateSharedSecret()

        // Never encrypt under the shared secret directly; run it through a KDF.
        let aesKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: encapsulation.sharedSecret,
            info: Self.info,
            outputByteCount: 32
        )

        let box = try AES.GCM.seal(plaintext, using: aesKey)
        return Message(kemCiphertext: encapsulation.ciphertext, sealedBox: box.combined!)
    }

    private func openUniversal(_ message: Message, with privateKey: PQ.XWing.PrivateKey) throws -> Data {
        let sharedSecret = try privateKey.decapsulate(message.kemCiphertext)

        let aesKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: sharedSecret,
            info: Self.info,
            outputByteCount: 32
        )

        return try AES.GCM.open(AES.GCM.SealedBox(combined: message.sealedBox), using: aesKey)
    }

    func testUniversalAESFlow() throws {
        let recipientKey = try PQ.XWing.PrivateKey()
        let published = recipientKey.publicKey.rawRepresentation

        let plaintext = Data("attack at dawn".utf8)
        let message = try sealUniversal(plaintext, to: published)

        XCTAssertEqual(try openUniversal(message, with: recipientKey), plaintext)

        // Tampering with the box must fail authentication rather than return
        // garbage plaintext.
        var tampered = Array(message.sealedBox)
        tampered[0] ^= 0x01
        XCTAssertThrowsError(
            try openUniversal(Message(kemCiphertext: message.kemCiphertext, sealedBox: Data(tampered)),
                              with: recipientKey)
        )
    }

    // MARK: - iOS 17+ generic over CryptoKit's KEM protocols

    @available(iOS 17.0, macOS 14.0, tvOS 17.0, watchOS 10.0, *)
    private func seal<K: KEMPublicKey>(_ plaintext: Data, to publicKey: K) throws -> Message {
        let result = try publicKey.encapsulate()

        let aesKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: result.sharedSecret,
            info: Self.info,
            outputByteCount: 32
        )

        let box = try AES.GCM.seal(plaintext, using: aesKey)
        return Message(kemCiphertext: result.encapsulated, sealedBox: box.combined!)
    }

    @available(iOS 17.0, macOS 14.0, tvOS 17.0, watchOS 10.0, *)
    private func open<K: KEMPrivateKey>(_ message: Message, with privateKey: K) throws -> Data {
        let sharedSecret = try privateKey.decapsulate(message.kemCiphertext)

        let aesKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: sharedSecret,
            info: Self.info,
            outputByteCount: 32
        )

        return try AES.GCM.open(AES.GCM.SealedBox(combined: message.sealedBox), using: aesKey)
    }

    /// The generic helpers accept any family without naming a concrete type.
    @available(iOS 17.0, macOS 14.0, tvOS 17.0, watchOS 10.0, *)
    private func assertGenericFlow<K: KEMPrivateKey>(
        _ privateKey: K,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let plaintext = Data("retreat at dusk".utf8)
        let message = try seal(plaintext, to: privateKey.publicKey)
        XCTAssertEqual(try open(message, with: privateKey), plaintext, file: file, line: line)
    }

    func testGenericAESFlow() throws {
        guard #available(iOS 17.0, macOS 14.0, tvOS 17.0, watchOS 10.0, *) else {
            throw XCTSkip("CryptoKit's KEM protocols require iOS 17 / macOS 14")
        }

        try assertGenericFlow(try PQ.MLKEM768.PrivateKey())
        try assertGenericFlow(try PQ.MLKEM1024.PrivateKey())
        try assertGenericFlow(try PQ.XWing.PrivateKey())
        try assertGenericFlow(try PQ.HybridMLKEM1024X25519.PrivateKey())
    }

    /// The same generic helpers also accept CryptoKit's native implementations,
    /// so raising the deployment target to iOS 26 does not change call sites.
    func testGenericAESFlowAcceptsNativeCryptoKitKeys() throws {
        guard #available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, *) else {
            throw XCTSkip("CryptoKit's native ML-KEM requires iOS 26 / macOS 26")
        }

        try assertGenericFlow(try CryptoKit.MLKEM768.PrivateKey())
        try assertGenericFlow(try CryptoKit.XWingMLKEM768X25519.PrivateKey())
    }

    /// A message sealed to a `PQ` key opens under CryptoKit's native key for the
    /// same standard, which is what makes a staged migration safe.
    func testUniversalFlowInteroperatesWithNativeCryptoKit() throws {
        guard #available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, *) else {
            throw XCTSkip("CryptoKit's native X-Wing requires iOS 26 / macOS 26")
        }

        // Recipient is on a new OS and uses CryptoKit directly.
        let nativeKey = try CryptoKit.XWingMLKEM768X25519.PrivateKey()

        // Sender is on an older OS and uses this package.
        let plaintext = Data("hold the line".utf8)
        let message = try sealUniversal(plaintext, to: nativeKey.publicKey.rawRepresentation)

        // Recipient opens it with no knowledge of this package.
        let sharedSecret = try nativeKey.decapsulate(message.kemCiphertext)
        let aesKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: sharedSecret,
            info: Self.info,
            outputByteCount: 32
        )
        let opened = try AES.GCM.open(AES.GCM.SealedBox(combined: message.sealedBox), using: aesKey)

        XCTAssertEqual(opened, plaintext)
    }
}
