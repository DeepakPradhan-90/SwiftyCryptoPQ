import Foundation
import CryptoKit

public enum X25519Error: Error, LocalizedError {
    case keyPairGenerationFailed
    case keyExchangeFailed
    case invalidPublicKeyLength
    case invalidPrivateKeyLength

    public var errorDescription: String? {
        switch self {
        case .keyPairGenerationFailed: return "X25519 keypair generation failed"
        case .keyExchangeFailed: return "X25519 key exchange failed"
        case .invalidPublicKeyLength: return "Invalid X25519 public key length (must be 32 bytes)"
        case .invalidPrivateKeyLength: return "Invalid X25519 private key length (must be 32 bytes)"
        }
    }
}

public enum X25519 {
    /// Generates a new X25519 keypair.
    /// Returns 32-byte private and public key representations.
    public static func generateKeyPair() throws -> (privateKey: [UInt8], publicKey: [UInt8]) {
        let privateKeyObj = Curve25519.KeyAgreement.PrivateKey()
        let publicKeyObj = privateKeyObj.publicKey

        let privateKeyBytes = Array(privateKeyObj.rawRepresentation)
        let publicKeyBytes = Array(publicKeyObj.rawRepresentation)

        return (privateKeyBytes, publicKeyBytes)
    }

    /// Derives the 32-byte public key for a private key, i.e. X25519(sk, basepoint).
    public static func publicKey(for privateKey: [UInt8]) throws -> [UInt8] {
        guard privateKey.count == 32 else {
            throw X25519Error.invalidPrivateKeyLength
        }

        do {
            let privKeyObj = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            return Array(privKeyObj.publicKey.rawRepresentation)
        } catch {
            throw X25519Error.keyPairGenerationFailed
        }
    }

    /// Performs an X25519 Diffie-Hellman key exchange and yields the 32-byte
    /// shared secret to `body` without ever copying it into an `Array`.
    ///
    /// Prefer this over `keyExchange(privateKey:peerPublicKey:)`. CryptoKit's
    /// `SharedSecret` manages its own locked, self-zeroing storage, and copying
    /// the bytes out into a plain `[UInt8]` discards those protections.
    public static func withSharedSecret<T>(
        privateKey: [UInt8],
        peerPublicKey: [UInt8],
        _ body: (UnsafeRawBufferPointer) throws -> T
    ) throws -> T {
        guard privateKey.count == 32 else {
            throw X25519Error.invalidPrivateKeyLength
        }
        guard peerPublicKey.count == 32 else {
            throw X25519Error.invalidPublicKeyLength
        }

        let sharedSecret: SharedSecret
        do {
            let privKeyObj = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            let pubKeyObj = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
            sharedSecret = try privKeyObj.sharedSecretFromKeyAgreement(with: pubKeyObj)
        } catch {
            throw X25519Error.keyExchangeFailed
        }

        // Errors thrown by `body` are the caller's, not key agreement failures,
        // so they propagate rather than being folded into keyExchangeFailed.
        return try sharedSecret.withUnsafeBytes(body)
    }

    /// Performs standard X25519 Diffie-Hellman key exchange.
    /// Returns the 32-byte shared secret.
    ///
    /// This materializes the shared secret as an `Array`, which Swift may copy
    /// beyond your control. Use `withSharedSecret(privateKey:peerPublicKey:_:)`
    /// where the secret does not need to outlive the call.
    public static func keyExchange(privateKey: [UInt8], peerPublicKey: [UInt8]) throws -> [UInt8] {
        try withSharedSecret(privateKey: privateKey, peerPublicKey: peerPublicKey) { Array($0) }
    }
}
