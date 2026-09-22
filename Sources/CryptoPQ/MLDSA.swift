import Foundation
import CryptoPQC

public enum MLDSAError: Error, LocalizedError {
    case keyGenerationFailed
    case signingFailed
    case verificationFailed
    case invalidPublicKeyLength
    case invalidPrivateKeyLength
    case invalidSignatureLength
    case contextTooLong

    public var errorDescription: String? {
        switch self {
        case .keyGenerationFailed: return "ML-DSA key generation failed"
        case .signingFailed: return "ML-DSA signing failed"
        case .verificationFailed: return "ML-DSA signature verification failed"
        case .invalidPublicKeyLength: return "Invalid ML-DSA public key length"
        case .invalidPrivateKeyLength: return "Invalid ML-DSA private key length"
        case .invalidSignatureLength: return "Invalid ML-DSA signature length"
        case .contextTooLong: return "ML-DSA context string may not exceed 255 bytes"
        }
    }
}

public enum MLDSA {
    public enum Mode {
        case dsa44
        case dsa65
        case dsa87

        public var publicKeyLength: Int {
            switch self {
            case .dsa44: return Int(CRYPTO_PQC_MLDSA44_PUBLICKEYBYTES)
            case .dsa65: return Int(CRYPTO_PQC_MLDSA65_PUBLICKEYBYTES)
            case .dsa87: return Int(CRYPTO_PQC_MLDSA87_PUBLICKEYBYTES)
            }
        }

        public var privateKeyLength: Int {
            switch self {
            case .dsa44: return Int(CRYPTO_PQC_MLDSA44_SECRETKEYBYTES)
            case .dsa65: return Int(CRYPTO_PQC_MLDSA65_SECRETKEYBYTES)
            case .dsa87: return Int(CRYPTO_PQC_MLDSA87_SECRETKEYBYTES)
            }
        }

        public var signatureLength: Int {
            switch self {
            case .dsa44: return Int(CRYPTO_PQC_MLDSA44_BYTES)
            case .dsa65: return Int(CRYPTO_PQC_MLDSA65_BYTES)
            case .dsa87: return Int(CRYPTO_PQC_MLDSA87_BYTES)
            }
        }
    }

    public struct KeyPair {
        public let publicKey: [UInt8]
        public let privateKey: [UInt8]

        public init(publicKey: [UInt8], privateKey: [UInt8]) {
            self.publicKey = publicKey
            self.privateKey = privateKey
        }
    }

    /// Generates a new ML-DSA keypair. Defaults to .dsa65 (standard intermediate level) if not specified.
    public static func generateKeyPair(mode: Mode = .dsa65) throws -> KeyPair {
        var pk = [UInt8](repeating: 0, count: mode.publicKeyLength)
        var sk = [UInt8](repeating: 0, count: mode.privateKeyLength)

        let result: Int32
        switch mode {
        case .dsa44:
            result = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(&pk, &sk)
        case .dsa65:
            result = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(&pk, &sk)
        case .dsa87:
            result = PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(&pk, &sk)
        }

        guard result == 0 else {
            throw MLDSAError.keyGenerationFailed
        }

        return KeyPair(publicKey: pk, privateKey: sk)
    }

    /// Signs a message using an ML-DSA private key. Mode is automatically inferred.
    public static func sign(message: [UInt8], privateKey: [UInt8], context: [UInt8] = []) throws -> [UInt8] {
        let mode: Mode
        if privateKey.count == Mode.dsa44.privateKeyLength {
            mode = .dsa44
        } else if privateKey.count == Mode.dsa65.privateKeyLength {
            mode = .dsa65
        } else if privateKey.count == Mode.dsa87.privateKeyLength {
            mode = .dsa87
        } else {
            throw MLDSAError.invalidPrivateKeyLength
        }
        return try sign(message: message, privateKey: privateKey, mode: mode, context: context)
    }

    /// Signs a message using an ML-DSA private key for a specific mode.
    ///
    /// `context` is the FIPS 204 context string, which defaults to empty and is
    /// bound into the signature; verification must supply the same value.
    public static func sign(message: [UInt8], privateKey: [UInt8], mode: Mode, context: [UInt8] = []) throws -> [UInt8] {
        guard privateKey.count == mode.privateKeyLength else {
            throw MLDSAError.invalidPrivateKeyLength
        }
        guard context.count <= 255 else {
            throw MLDSAError.contextTooLong
        }

        var sig = [UInt8](repeating: 0, count: mode.signatureLength)
        var sigLen: Int = mode.signatureLength

        let result: Int32 = context.withUnsafeBufferPointer { ctx in
            switch mode {
            case .dsa44:
                return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(&sig, &sigLen, message, message.count, ctx.baseAddress, ctx.count, privateKey)
            case .dsa65:
                return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx(&sig, &sigLen, message, message.count, ctx.baseAddress, ctx.count, privateKey)
            case .dsa87:
                return PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx(&sig, &sigLen, message, message.count, ctx.baseAddress, ctx.count, privateKey)
            }
        }

        guard result == 0 else {
            throw MLDSAError.signingFailed
        }

        // Dilithium's PQClean implementation has a fixed maximum signature size and returns actual signature size in sigLen.
        // We can slice/resize the signature to the exact actual size.
        if sig.count > sigLen {
            sig = Array(sig[0..<sigLen])
        }

        return sig
    }

    /// Verifies a signature for a message using an ML-DSA public key. Mode is automatically inferred.
    public static func verify(message: [UInt8], signature: [UInt8], publicKey: [UInt8], context: [UInt8] = []) throws -> Bool {
        let mode: Mode
        if publicKey.count == Mode.dsa44.publicKeyLength {
            mode = .dsa44
        } else if publicKey.count == Mode.dsa65.publicKeyLength {
            mode = .dsa65
        } else if publicKey.count == Mode.dsa87.publicKeyLength {
            mode = .dsa87
        } else {
            throw MLDSAError.invalidPublicKeyLength
        }
        return try verify(message: message, signature: signature, publicKey: publicKey, mode: mode, context: context)
    }

    /// Verifies a signature for a message using an ML-DSA public key for a specific mode.
    public static func verify(message: [UInt8], signature: [UInt8], publicKey: [UInt8], mode: Mode, context: [UInt8] = []) throws -> Bool {
        guard publicKey.count == mode.publicKeyLength else {
            throw MLDSAError.invalidPublicKeyLength
        }

        // Dilithium PQClean signatures can be up to mode.signatureLength but could be smaller if resized
        guard signature.count <= mode.signatureLength else {
            throw MLDSAError.invalidSignatureLength
        }
        guard context.count <= 255 else {
            throw MLDSAError.contextTooLong
        }

        let result: Int32 = context.withUnsafeBufferPointer { ctx in
            switch mode {
            case .dsa44:
                return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(signature, signature.count, message, message.count, ctx.baseAddress, ctx.count, publicKey)
            case .dsa65:
                return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(signature, signature.count, message, message.count, ctx.baseAddress, ctx.count, publicKey)
            case .dsa87:
                return PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx(signature, signature.count, message, message.count, ctx.baseAddress, ctx.count, publicKey)
            }
        }

        return result == 0
    }
}
