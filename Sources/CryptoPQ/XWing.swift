import Foundation
import CryptoKit
import CryptoPQC

public enum XWingError: Error, LocalizedError {
    case keyGenerationFailed
    case encapsulationFailed
    case decapsulationFailed
    case invalidPublicKeyLength
    case invalidPrivateKeyLength
    case invalidCiphertextLength
    case invalidSeedLength

    public var errorDescription: String? {
        switch self {
        case .keyGenerationFailed: return "X-Wing key generation failed"
        case .encapsulationFailed: return "X-Wing encapsulation failed"
        case .decapsulationFailed: return "X-Wing decapsulation failed"
        case .invalidPublicKeyLength: return "Invalid X-Wing encapsulation key length (must be 1216 bytes)"
        case .invalidPrivateKeyLength: return "Invalid X-Wing decapsulation key length (must be 32 bytes)"
        case .invalidCiphertextLength: return "Invalid X-Wing ciphertext length (must be 1120 bytes)"
        case .invalidSeedLength: return "Invalid X-Wing encapsulation seed length (must be 64 bytes)"
        }
    }
}

/// X-Wing, the hybrid KEM combining ML-KEM-768 and X25519, as specified in
/// draft-connolly-cfrg-xwing-kem-10.
public enum XWingX25519 {
    public static let mlkemPublicKeyLength = 1184
    public static let mlkemCiphertextLength = 1088
    public static let x25519KeyLength = 32

    public static let publicKeyLength = 1216   // 1184 + 32
    public static let privateKeyLength = 32    // a seed, expanded with SHAKE256
    public static let ciphertextLength = 1120  // 1088 + 32
    public static let sharedSecretLength = 32
    public static let encapsulationSeedLength = 64

    /// The 6-byte ASCII string `\.//^\`, appended last to the combiner input.
    private static let xwingLabel: [UInt8] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]

    public struct KeyPair {
        public let publicKey: [UInt8]
        public let privateKey: [UInt8]

        public init(publicKey: [UInt8], privateKey: [UInt8]) {
            self.publicKey = publicKey
            self.privateKey = privateKey
        }
    }

    /// The component keys recovered from a 32-byte decapsulation key.
    private struct ExpandedKey {
        var mlkemPrivateKey: [UInt8]
        var x25519PrivateKey: [UInt8]
        var mlkemPublicKey: [UInt8]
        var x25519PublicKey: [UInt8]

        mutating func wipeSecrets() {
            wipe(&mlkemPrivateKey)
            wipe(&x25519PrivateKey)
        }
    }

    /// `expandDecapsulationKey` from §5.2.
    private static func expandDecapsulationKey(_ seed: [UInt8]) throws -> ExpandedKey {
        guard seed.count == privateKeyLength else {
            throw XWingError.invalidPrivateKeyLength
        }

        var expanded = FIPS202.shake256(seed, outputLength: 96)
        defer { wipe(&expanded) }

        let mlkemSeed = Array(expanded[0..<64])   // d || z
        let skX = Array(expanded[64..<96])

        let mlkemPair = try MLKEM.generateKeyPair(mode: .kem768, seed: mlkemSeed)
        let pkX = try X25519.publicKey(for: skX)

        return ExpandedKey(
            mlkemPrivateKey: mlkemPair.privateKey,
            x25519PrivateKey: skX,
            mlkemPublicKey: mlkemPair.publicKey,
            x25519PublicKey: pkX
        )
    }

    /// `Combiner` from §5.3: SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel).
    private static func combiner(ssM: [UInt8], ssX: [UInt8], ctX: [UInt8], pkX: [UInt8]) -> [UInt8] {
        var input = [UInt8]()
        input.reserveCapacity(ssM.count + ssX.count + ctX.count + pkX.count + xwingLabel.count)
        input.append(contentsOf: ssM)
        input.append(contentsOf: ssX)
        input.append(contentsOf: ctX)
        input.append(contentsOf: pkX)
        input.append(contentsOf: xwingLabel)
        defer { wipe(&input) }

        return FIPS202.sha3_256(input)
    }

    /// Generates a new X-Wing keypair: a 32-byte decapsulation key and a
    /// 1216-byte encapsulation key.
    public static func generateKeyPair() throws -> KeyPair {
        var seed = [UInt8](repeating: 0, count: privateKeyLength)
        let status = seed.withUnsafeMutableBytes { raw in
            SecRandomCopyBytes(kSecRandomDefault, raw.count, raw.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw XWingError.keyGenerationFailed
        }
        return try generateKeyPair(seed: seed)
    }

    /// `GenerateKeyPairDerand` from §5.2.1.
    public static func generateKeyPair(seed: [UInt8]) throws -> KeyPair {
        var expanded = try expandDecapsulationKey(seed)
        defer { expanded.wipeSecrets() }

        var pk = [UInt8]()
        pk.reserveCapacity(publicKeyLength)
        pk.append(contentsOf: expanded.mlkemPublicKey)
        pk.append(contentsOf: expanded.x25519PublicKey)

        return KeyPair(publicKey: pk, privateKey: seed)
    }

    /// Encapsulates a shared secret against the recipient's encapsulation key.
    public static func encapsulate(publicKey: [UInt8]) throws -> (sharedSecret: [UInt8], ciphertext: [UInt8]) {
        var eseed = [UInt8](repeating: 0, count: encapsulationSeedLength)
        let status = eseed.withUnsafeMutableBytes { raw in
            SecRandomCopyBytes(kSecRandomDefault, raw.count, raw.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw XWingError.encapsulationFailed
        }
        defer { wipe(&eseed) }

        return try encapsulate(publicKey: publicKey, eseed: eseed)
    }

    /// `EncapsulateDerand` from §5.4.1.
    public static func encapsulate(publicKey: [UInt8], eseed: [UInt8]) throws -> (sharedSecret: [UInt8], ciphertext: [UInt8]) {
        guard publicKey.count == publicKeyLength else {
            throw XWingError.invalidPublicKeyLength
        }
        guard eseed.count == encapsulationSeedLength else {
            throw XWingError.invalidSeedLength
        }

        let pkM = Array(publicKey[0..<mlkemPublicKeyLength])
        let pkX = Array(publicKey[mlkemPublicKeyLength..<publicKeyLength])

        var ekX = Array(eseed[32..<64])
        defer { wipe(&ekX) }

        let ctX = try X25519.publicKey(for: ekX)
        var ssX = try X25519.keyExchange(privateKey: ekX, peerPublicKey: pkX)
        defer { wipe(&ssX) }

        // Propagates the FIPS 203 §7.2 encapsulation key check, as §5.4 requires.
        var (ssM, ctM) = try MLKEM.encapsulate(publicKey: pkM, mode: .kem768, randomness: Array(eseed[0..<32]))
        defer { wipe(&ssM) }

        let ss = combiner(ssM: ssM, ssX: ssX, ctX: ctX, pkX: pkX)

        var ct = [UInt8]()
        ct.reserveCapacity(ciphertextLength)
        ct.append(contentsOf: ctM)
        ct.append(contentsOf: ctX)

        return (ss, ct)
    }

    /// Decapsulates a shared secret from an X-Wing ciphertext.
    public static func decapsulate(ciphertext: [UInt8], privateKey: [UInt8]) throws -> [UInt8] {
        guard ciphertext.count == ciphertextLength else {
            throw XWingError.invalidCiphertextLength
        }

        var expanded = try expandDecapsulationKey(privateKey)
        defer { expanded.wipeSecrets() }

        let ctM = Array(ciphertext[0..<mlkemCiphertextLength])
        let ctX = Array(ciphertext[mlkemCiphertextLength..<ciphertextLength])

        var ssM = try MLKEM.decapsulate(ciphertext: ctM, privateKey: expanded.mlkemPrivateKey, mode: .kem768)
        defer { wipe(&ssM) }

        var ssX = try X25519.keyExchange(privateKey: expanded.x25519PrivateKey, peerPublicKey: ctX)
        defer { wipe(&ssX) }

        return combiner(ssM: ssM, ssX: ssX, ctX: ctX, pkX: expanded.x25519PublicKey)
    }
}
