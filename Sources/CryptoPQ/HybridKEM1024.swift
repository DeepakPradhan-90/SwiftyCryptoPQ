import Foundation
import CryptoKit
import CryptoPQC

public enum HybridKEM1024Error: Error, LocalizedError {
    case keyGenerationFailed
    case encapsulationFailed
    case decapsulationFailed
    case invalidPublicKeyLength
    case invalidPrivateKeyLength
    case invalidCiphertextLength

    public var errorDescription: String? {
        switch self {
        case .keyGenerationFailed: return "Hybrid-KEM-1024 key generation failed"
        case .encapsulationFailed: return "Hybrid-KEM-1024 encapsulation failed"
        case .decapsulationFailed: return "Hybrid-KEM-1024 decapsulation failed"
        case .invalidPublicKeyLength: return "Invalid Hybrid-KEM-1024 public key length (must be 1600 bytes)"
        case .invalidPrivateKeyLength: return "Invalid Hybrid-KEM-1024 private key length (must be 3232 bytes)"
        case .invalidCiphertextLength: return "Invalid Hybrid-KEM-1024 ciphertext length (must be 1600 bytes)"
        }
    }
}

public enum HybridKEM1024 {
    public static let mlkemPublicKeyLength = 1568
    public static let mlkemPrivateKeyLength = 3168
    public static let mlkemCiphertextLength = 1568
    public static let x25519KeyLength = 32

    public static let publicKeyLength = 1600   // 1568 + 32
    public static let privateKeyLength = 3232  // 3168 + 32 + 32
    public static let ciphertextLength = 1600  // 1568 + 32
    public static let sharedSecretLength = 64  // SHA-512 output

    private static let label: [UInt8] = Array("HYBRID-MLKEM1024-X25519".utf8)

    public struct KeyPair {
        public let publicKey: [UInt8]
        public let privateKey: [UInt8]

        public init(publicKey: [UInt8], privateKey: [UInt8]) {
            self.publicKey = publicKey
            self.privateKey = privateKey
        }
    }

    /// Generates a new Hybrid-KEM-1024 keypair.
    public static func generateKeyPair() throws -> KeyPair {
        // 1. Generate ML-KEM-1024 keypair
        let mlkemPair = try MLKEM.generateKeyPair(mode: .kem1024)

        // 2. Generate X25519 keypair
        var (skX, pkX) = try X25519.generateKeyPair()
        defer { wipe(&skX) }

        // 3. Assemble public key: pk_M || pk_X
        var pk = [UInt8]()
        pk.reserveCapacity(publicKeyLength)
        pk.append(contentsOf: mlkemPair.publicKey)
        pk.append(contentsOf: pkX)

        // 4. Assemble private key: sk_M || sk_X || pk_X
        var sk = [UInt8]()
        sk.reserveCapacity(privateKeyLength)
        sk.append(contentsOf: mlkemPair.privateKey)
        sk.append(contentsOf: skX)
        sk.append(contentsOf: pkX)

        return KeyPair(publicKey: pk, privateKey: sk)
    }

    /// Encapsulates a shared secret using the recipient's hybrid public key.
    public static func encapsulate(publicKey: [UInt8]) throws -> (sharedSecret: [UInt8], ciphertext: [UInt8]) {
        guard publicKey.count == publicKeyLength else {
            throw HybridKEM1024Error.invalidPublicKeyLength
        }

        // 1. Parse public key: pk_M (1568 bytes) || pk_X (32 bytes)
        let pkM = Array(publicKey[0..<mlkemPublicKeyLength])
        let pkX = Array(publicKey[mlkemPublicKeyLength..<publicKeyLength])

        // 2. Generate ephemeral X25519 keypair
        var (ekX, ctX) = try X25519.generateKeyPair()
        defer { wipe(&ekX) }

        // 3. Compute X25519 shared secret: ss_X = X25519(ek_X, pk_X)
        var ssX = try X25519.keyExchange(privateKey: ekX, peerPublicKey: pkX)
        defer { wipe(&ssX) }

        // 4. Encapsulate ML-KEM-1024: ss_M (32 bytes), ct_M (1568 bytes)
        var (ssM, ctM) = try MLKEM.encapsulate(publicKey: pkM, mode: .kem1024)
        defer { wipe(&ssM) }

        // 5. Combine the shared secrets using SHA-512:
        // ss = SHA512(Label || ss_M || ss_X || ct_X || pk_X)
        var inputBuffer = [UInt8]()
        inputBuffer.reserveCapacity(label.count + ssM.count + ssX.count + ctX.count + pkX.count)
        inputBuffer.append(contentsOf: label)
        inputBuffer.append(contentsOf: ssM)
        inputBuffer.append(contentsOf: ssX)
        inputBuffer.append(contentsOf: ctX)
        inputBuffer.append(contentsOf: pkX)

        let digest = SHA512.hash(data: inputBuffer)
        let ss = Array(digest)
        wipe(&inputBuffer)

        // 6. Construct ciphertext: ct_M (1568 bytes) || ct_X (32 bytes)
        var ct = [UInt8]()
        ct.reserveCapacity(ciphertextLength)
        ct.append(contentsOf: ctM)
        ct.append(contentsOf: ctX)

        return (ss, ct)
    }

    /// Decapsulates a shared secret from a hybrid ciphertext using the recipient's hybrid private key.
    public static func decapsulate(ciphertext: [UInt8], privateKey: [UInt8]) throws -> [UInt8] {
        guard ciphertext.count == ciphertextLength else {
            throw HybridKEM1024Error.invalidCiphertextLength
        }
        guard privateKey.count == privateKeyLength else {
            throw HybridKEM1024Error.invalidPrivateKeyLength
        }

        // 1. Parse ciphertext: ct_M (1568 bytes) || ct_X (32 bytes)
        let ctM = Array(ciphertext[0..<mlkemCiphertextLength])
        let ctX = Array(ciphertext[mlkemCiphertextLength..<ciphertextLength])

        // 2. Parse private key: sk_M (3168 bytes) || sk_X (32 bytes) || pk_X (32 bytes)
        var skM = Array(privateKey[0..<mlkemPrivateKeyLength])
        defer { wipe(&skM) }
        var skX = Array(privateKey[mlkemPrivateKeyLength..<(mlkemPrivateKeyLength + x25519KeyLength)])
        defer { wipe(&skX) }
        let pkX = Array(privateKey[(mlkemPrivateKeyLength + x25519KeyLength)..<privateKeyLength])

        // 3. Decapsulate ML-KEM-1024 shared secret: ss_M
        var ssM = try MLKEM.decapsulate(ciphertext: ctM, privateKey: skM, mode: .kem1024)
        defer { wipe(&ssM) }

        // 4. Compute X25519 shared secret: ss_X = X25519(sk_X, ct_X)
        var ssX = try X25519.keyExchange(privateKey: skX, peerPublicKey: ctX)
        defer { wipe(&ssX) }

        // 5. Combine the shared secrets using SHA-512:
        // ss = SHA512(Label || ss_M || ss_X || ct_X || pk_X)
        var inputBuffer = [UInt8]()
        inputBuffer.reserveCapacity(label.count + ssM.count + ssX.count + ctX.count + pkX.count)
        inputBuffer.append(contentsOf: label)
        inputBuffer.append(contentsOf: ssM)
        inputBuffer.append(contentsOf: ssX)
        inputBuffer.append(contentsOf: ctX)
        inputBuffer.append(contentsOf: pkX)

        let digest = SHA512.hash(data: inputBuffer)
        wipe(&inputBuffer)
        return Array(digest)
    }
}
