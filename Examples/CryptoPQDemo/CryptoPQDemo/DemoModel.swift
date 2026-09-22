import CryptoKit
import CryptoPQ
import Foundation

/// Drives the demo: a KEM establishes a shared secret, HKDF turns it into an
/// AEAD key, and ML-DSA-65 signs the bytes that would go on the wire.
@MainActor
final class DemoModel: ObservableObject {
    enum KEMKind: String, CaseIterable, Identifiable {
        case mlkem768 = "ML-KEM-768"
        case mlkem1024 = "ML-KEM-1024"
        case xwing = "X-Wing"

        var id: String { rawValue }
    }

    enum CipherKind: String, CaseIterable, Identifiable {
        case aesGCM = "AES-GCM"
        case chaChaPoly = "ChaChaPoly"

        var id: String { rawValue }

        var detail: String {
            switch self {
            case .aesGCM: return "AES-256-GCM"
            case .chaChaPoly: return "ChaCha20-Poly1305"
            }
        }
    }

    @Published var kem: KEMKind = .xwing {
        didSet { if kem != oldValue { regenerateKeys() } }
    }

    @Published var cipher: CipherKind = .aesGCM

    @Published var plaintext = "Meet at the north gate after sunset."
    @Published var status = "Generating keys…"
    @Published var recovered = ""
    @Published var signatureValid: Bool?
    @Published var steps: [String] = []
    @Published var isBusy = false

    private var party: (any KEMParty)?
    private var signer: MLDSA.KeyPair?
    private var envelope: Envelope?

    private static let signatureContext = Array("CryptoPQDemo".utf8)

    init() {
        regenerateKeys()
    }

    func regenerateKeys() {
        isBusy = true
        envelope = nil
        recovered = ""
        signatureValid = nil
        steps = []
        status = "Generating keys…"

        do {
            let party = try Self.makeParty(kem)
            let signer = try MLDSA.generateKeyPair(mode: .dsa65)
            self.party = party
            self.signer = signer
            status = "\(kem.rawValue) recipient key and ML-DSA-65 signing key are ready."
            steps = [
                "Public key \(party.publicKeyByteCount) bytes, private key \(party.privateKeyByteCount) bytes.",
                "ML-DSA-65 public key \(signer.publicKey.count) bytes."
            ]
        } catch {
            party = nil
            signer = nil
            status = error.localizedDescription
        }
        isBusy = false
    }

    func encryptAndSign() {
        guard let party, let signer else {
            status = "Generate keys first."
            return
        }
        guard let message = plaintext.data(using: .utf8), !message.isEmpty else {
            status = "Enter a message to encrypt."
            return
        }

        isBusy = true
        recovered = ""
        signatureValid = nil
        defer { isBusy = false }

        do {
            let encapsulation = try party.encapsulate()
            let aesKey = Self.deriveKey(from: encapsulation.sharedSecret, kem: kem, cipher: cipher)
            let sealed = try Self.seal(message, using: aesKey, cipher: cipher)

            var transcript = Data()
            transcript.append(encapsulation.ciphertext)
            transcript.append(sealed)
            let signature = try MLDSA.sign(
                message: Array(transcript),
                privateKey: signer.privateKey,
                mode: .dsa65,
                context: Self.signatureContext
            )

            envelope = Envelope(
                kemCiphertext: encapsulation.ciphertext,
                sealed: sealed,
                signature: Data(signature),
                kem: kem,
                cipher: cipher
            )
            status = "Sealed with \(cipher.detail) and signed with ML-DSA-65."
            steps = [
                "Encapsulated a shared secret. KEM ciphertext is \(encapsulation.ciphertext.count) bytes.",
                "Derived a 256-bit \(cipher.detail) key with HKDF-SHA256.",
                "Sealed box is \(sealed.count) bytes.",
                "Signature over the ciphertext and the box is \(signature.count) bytes."
            ]
        } catch {
            envelope = nil
            status = error.localizedDescription
        }
    }

    func decryptAndVerify() {
        guard let party, let signer, let envelope else {
            status = "Encrypt a message first."
            return
        }

        isBusy = true
        defer { isBusy = false }

        guard envelope.kem == kem, envelope.cipher == cipher else {
            recovered = ""
            signatureValid = nil
            status = "This box was sealed with \(envelope.kem.rawValue) and \(envelope.cipher.detail). Switch back to open it."
            return
        }

        do {
            var transcript = Data()
            transcript.append(envelope.kemCiphertext)
            transcript.append(envelope.sealed)
            let valid = try MLDSA.verify(
                message: Array(transcript),
                signature: Array(envelope.signature),
                publicKey: signer.publicKey,
                mode: .dsa65,
                context: Self.signatureContext
            )
            signatureValid = valid
            guard valid else {
                recovered = ""
                status = "ML-DSA-65 rejected the signature. The ciphertext was not opened."
                return
            }

            let sharedSecret = try party.decapsulate(envelope.kemCiphertext)
            let key = Self.deriveKey(from: sharedSecret, kem: kem, cipher: cipher)
            let opened = try Self.open(envelope.sealed, using: key, cipher: cipher)
            recovered = String(decoding: opened, as: UTF8.self)
            status = "Signature valid. \(cipher.detail) opened the message."
            steps = [
                "ML-DSA-65 accepted the signature over the KEM ciphertext and the sealed box.",
                "Decapsulation recovered the same shared secret.",
                "HKDF-SHA256 reproduced the \(cipher.detail) key.",
                "Plaintext is \(opened.count) bytes."
            ]
        } catch {
            recovered = ""
            signatureValid = nil
            status = error.localizedDescription
        }
    }

    private static func deriveKey(from sharedSecret: SymmetricKey, kem: KEMKind, cipher: CipherKind) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: sharedSecret,
            info: Data("CryptoPQDemo/\(kem.rawValue)/\(cipher.rawValue)/v1".utf8),
            outputByteCount: 32
        )
    }

    private static func seal(_ plaintext: Data, using key: SymmetricKey, cipher: CipherKind) throws -> Data {
        switch cipher {
        case .aesGCM:
            guard let combined = try AES.GCM.seal(plaintext, using: key).combined else {
                throw DemoError.sealFailed
            }
            return combined
        case .chaChaPoly:
            return try ChaChaPoly.seal(plaintext, using: key).combined
        }
    }

    private static func open(_ sealed: Data, using key: SymmetricKey, cipher: CipherKind) throws -> Data {
        switch cipher {
        case .aesGCM:
            return try AES.GCM.open(try AES.GCM.SealedBox(combined: sealed), using: key)
        case .chaChaPoly:
            return try ChaChaPoly.open(try ChaChaPoly.SealedBox(combined: sealed), using: key)
        }
    }

    private static func makeParty(_ kind: KEMKind) throws -> any KEMParty {
        switch kind {
        case .mlkem768:
            return try Party(label: kind.rawValue, privateKey: PQ.MLKEM768.PrivateKey())
        case .mlkem1024:
            return try Party(label: kind.rawValue, privateKey: PQ.MLKEM1024.PrivateKey())
        case .xwing:
            return try Party(label: kind.rawValue, privateKey: PQ.XWing.PrivateKey())
        }
    }
}

private struct Envelope {
    let kemCiphertext: Data
    let sealed: Data
    let signature: Data
    let kem: DemoModel.KEMKind
    let cipher: DemoModel.CipherKind
}

private enum DemoError: Error, LocalizedError {
    case sealFailed

    var errorDescription: String? {
        switch self {
        case .sealFailed: return "AES-GCM did not produce a combined sealed box."
        }
    }
}

private protocol KEMParty: AnyObject {
    var publicKeyByteCount: Int { get }
    var privateKeyByteCount: Int { get }
    func encapsulate() throws -> Encapsulation
    func decapsulate(_ ciphertext: Data) throws -> SymmetricKey
}

private final class Party<Family: _KEMFamily>: KEMParty {
    let label: String
    let privateKey: KEMPrivateKeyOf<Family>

    init(label: String, privateKey: KEMPrivateKeyOf<Family>) {
        self.label = label
        self.privateKey = privateKey
    }

    var publicKeyByteCount: Int { KEMPublicKeyOf<Family>.byteCount }
    var privateKeyByteCount: Int { KEMPrivateKeyOf<Family>.byteCount }

    func encapsulate() throws -> Encapsulation {
        try privateKey.publicKey.encapsulateSharedSecret()
    }

    func decapsulate(_ ciphertext: Data) throws -> SymmetricKey {
        try privateKey.decapsulate(ciphertext)
    }
}
