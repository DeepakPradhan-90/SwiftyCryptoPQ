import Foundation
internal import CryptoPQC

public enum MLKEMError: Error, LocalizedError {
    case keyGenerationFailed
    case encapsulationFailed
    case decapsulationFailed
    case invalidPublicKeyLength
    case invalidPrivateKeyLength
    case invalidCiphertextLength
    case malformedPublicKey
    case malformedPrivateKey

    public var errorDescription: String? {
        switch self {
        case .keyGenerationFailed: return "ML-KEM key generation failed"
        case .encapsulationFailed: return "ML-KEM encapsulation failed"
        case .decapsulationFailed: return "ML-KEM decapsulation failed"
        case .invalidPublicKeyLength: return "Invalid ML-KEM public key length"
        case .invalidPrivateKeyLength: return "Invalid ML-KEM private key length"
        case .invalidCiphertextLength: return "Invalid ML-KEM ciphertext length"
        case .malformedPublicKey: return "ML-KEM encapsulation key failed the FIPS 203 modulus check"
        case .malformedPrivateKey: return "ML-KEM decapsulation key failed the FIPS 203 hash check"
        }
    }
}

public enum MLKEM {
    public enum Mode {
        case kem768
        case kem1024

        public var publicKeyLength: Int {
            switch self {
            case .kem768: return Int(CRYPTO_PQC_MLKEM768_PUBLICKEYBYTES)
            case .kem1024: return Int(CRYPTO_PQC_MLKEM1024_PUBLICKEYBYTES)
            }
        }

        public var privateKeyLength: Int {
            switch self {
            case .kem768: return Int(CRYPTO_PQC_MLKEM768_SECRETKEYBYTES)
            case .kem1024: return Int(CRYPTO_PQC_MLKEM1024_SECRETKEYBYTES)
            }
        }

        public var ciphertextLength: Int {
            switch self {
            case .kem768: return Int(CRYPTO_PQC_MLKEM768_CIPHERTEXTBYTES)
            case .kem1024: return Int(CRYPTO_PQC_MLKEM1024_CIPHERTEXTBYTES)
            }
        }

        public var sharedSecretLength: Int {
            switch self {
            case .kem768: return Int(CRYPTO_PQC_MLKEM768_BYTES)
            case .kem1024: return Int(CRYPTO_PQC_MLKEM1024_BYTES)
            }
        }

        /// The rank k of the module, i.e. the number of encoded polynomials in an encapsulation key.
        var rank: Int {
            switch self {
            case .kem768: return 3
            case .kem1024: return 4
            }
        }
    }

    private static let q: UInt16 = 3329

    /// FIPS 203 §7.2 encapsulation key check: every 12-bit coefficient must be
    /// reduced modulo q, so that ByteEncode12(ByteDecode12(ek)) round-trips.
    /// PQClean silently reduces malformed coefficients instead of rejecting them.
    public static func validate(publicKey: [UInt8], mode: Mode) throws {
        guard publicKey.count == mode.publicKeyLength else {
            throw MLKEMError.invalidPublicKeyLength
        }

        let encodedLength = 384 * mode.rank
        var index = 0
        while index < encodedLength {
            let b0 = UInt16(publicKey[index])
            let b1 = UInt16(publicKey[index + 1])
            let b2 = UInt16(publicKey[index + 2])
            let first = b0 | ((b1 & 0x0F) << 8)
            let second = (b1 >> 4) | (b2 << 4)
            guard first < q, second < q else {
                throw MLKEMError.malformedPublicKey
            }
            index += 3
        }
    }

    /// Extracts the encapsulation key embedded in a decapsulation key.
    ///
    /// FIPS 203 stores `dk = dk_PKE || ek || H(ek) || z`, so no recomputation is
    /// needed. The decapsulation key is validated first.
    public static func embeddedPublicKey(inPrivateKey privateKey: [UInt8], mode: Mode) throws -> [UInt8] {
        try validate(privateKey: privateKey, mode: mode)
        let ekStart = 384 * mode.rank
        return Array(privateKey[ekStart..<(ekStart + mode.publicKeyLength)])
    }

    /// FIPS 203 §7.3 decapsulation key check: the embedded H(ek) must match the
    /// embedded encapsulation key.
    public static func validate(privateKey: [UInt8], mode: Mode) throws {
        guard privateKey.count == mode.privateKeyLength else {
            throw MLKEMError.invalidPrivateKeyLength
        }

        // dk = dk_PKE || ek || H(ek) || z
        let ekStart = 384 * mode.rank
        let ekEnd = ekStart + mode.publicKeyLength
        let embeddedPublicKey = Array(privateKey[ekStart..<ekEnd])
        let embeddedHash = Array(privateKey[ekEnd..<(ekEnd + 32)])

        guard FIPS202.sha3_256(embeddedPublicKey) == embeddedHash else {
            throw MLKEMError.malformedPrivateKey
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

    /// Generates a new ML-KEM keypair.
    public static func generateKeyPair(mode: Mode) throws -> KeyPair {
        var pk = [UInt8](repeating: 0, count: mode.publicKeyLength)
        var sk = [UInt8](repeating: 0, count: mode.privateKeyLength)

        let result: Int32
        switch mode {
        case .kem768:
            result = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(&pk, &sk)
        case .kem1024:
            result = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(&pk, &sk)
        }

        guard result == 0 else {
            throw MLKEMError.keyGenerationFailed
        }

        return KeyPair(publicKey: pk, privateKey: sk)
    }

    /// Generates an ML-KEM keypair from caller-supplied randomness `d || z`
    /// (FIPS 203 `ML-KEM.KeyGen_internal`). Used by X-Wing and by known-answer tests.
    public static func generateKeyPair(mode: Mode, seed: [UInt8]) throws -> KeyPair {
        guard seed.count == 64 else {
            throw MLKEMError.keyGenerationFailed
        }

        var pk = [UInt8](repeating: 0, count: mode.publicKeyLength)
        var sk = [UInt8](repeating: 0, count: mode.privateKeyLength)

        let result: Int32
        switch mode {
        case .kem768:
            result = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(&pk, &sk, seed)
        case .kem1024:
            result = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(&pk, &sk, seed)
        }

        guard result == 0 else {
            throw MLKEMError.keyGenerationFailed
        }

        return KeyPair(publicKey: pk, privateKey: sk)
    }

    /// Encapsulates a shared secret using the recipient's public key.
    /// The mode is automatically inferred from the public key length.
    public static func encapsulate(publicKey: [UInt8]) throws -> (sharedSecret: [UInt8], ciphertext: [UInt8]) {
        let mode: Mode
        if publicKey.count == Mode.kem768.publicKeyLength {
            mode = .kem768
        } else if publicKey.count == Mode.kem1024.publicKeyLength {
            mode = .kem1024
        } else {
            throw MLKEMError.invalidPublicKeyLength
        }
        return try encapsulate(publicKey: publicKey, mode: mode)
    }

    /// Encapsulates a shared secret using the recipient's public key for a specific mode.
    public static func encapsulate(publicKey: [UInt8], mode: Mode) throws -> (sharedSecret: [UInt8], ciphertext: [UInt8]) {
        try validate(publicKey: publicKey, mode: mode)

        var ct = [UInt8](repeating: 0, count: mode.ciphertextLength)
        var ss = [UInt8](repeating: 0, count: mode.sharedSecretLength)

        let result: Int32
        switch mode {
        case .kem768:
            result = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(&ct, &ss, publicKey)
        case .kem1024:
            result = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(&ct, &ss, publicKey)
        }

        guard result == 0 else {
            throw MLKEMError.encapsulationFailed
        }

        return (ss, ct)
    }

    /// Encapsulates using caller-supplied randomness `m` (FIPS 203 `ML-KEM.Encaps_internal`).
    /// Used by X-Wing's derandomized encapsulation and by known-answer tests.
    public static func encapsulate(publicKey: [UInt8], mode: Mode, randomness: [UInt8]) throws -> (sharedSecret: [UInt8], ciphertext: [UInt8]) {
        try validate(publicKey: publicKey, mode: mode)
        guard randomness.count == 32 else {
            throw MLKEMError.encapsulationFailed
        }

        var ct = [UInt8](repeating: 0, count: mode.ciphertextLength)
        var ss = [UInt8](repeating: 0, count: mode.sharedSecretLength)

        let result: Int32
        switch mode {
        case .kem768:
            result = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(&ct, &ss, publicKey, randomness)
        case .kem1024:
            result = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(&ct, &ss, publicKey, randomness)
        }

        guard result == 0 else {
            throw MLKEMError.encapsulationFailed
        }

        return (ss, ct)
    }

    /// Decapsulates a shared secret from a ciphertext using the recipient's private key.
    /// The mode is automatically inferred from the private key length.
    public static func decapsulate(ciphertext: [UInt8], privateKey: [UInt8]) throws -> [UInt8] {
        let mode: Mode
        if privateKey.count == Mode.kem768.privateKeyLength {
            mode = .kem768
        } else if privateKey.count == Mode.kem1024.privateKeyLength {
            mode = .kem1024
        } else {
            throw MLKEMError.invalidPrivateKeyLength
        }
        return try decapsulate(ciphertext: ciphertext, privateKey: privateKey, mode: mode)
    }

    /// Decapsulates a shared secret from a ciphertext using the recipient's private key for a specific mode.
    public static func decapsulate(ciphertext: [UInt8], privateKey: [UInt8], mode: Mode) throws -> [UInt8] {
        try validate(privateKey: privateKey, mode: mode)
        guard ciphertext.count == mode.ciphertextLength else {
            throw MLKEMError.invalidCiphertextLength
        }

        var ss = [UInt8](repeating: 0, count: mode.sharedSecretLength)

        let result: Int32
        switch mode {
        case .kem768:
            result = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(&ss, ciphertext, privateKey)
        case .kem1024:
            result = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(&ss, ciphertext, privateKey)
        }

        guard result == 0 else {
            throw MLKEMError.decapsulationFailed
        }

        return ss
    }
}
