import Foundation
import CryptoKit

/// The result of encapsulating against a public key.
///
/// Mirrors CryptoKit's `KEM.EncapsulationResult`, which is only available from
/// iOS 17, so that the same shape is usable across every supported OS version.
/// On iOS 17 and later, `kemResult` converts to CryptoKit's type.
public struct Encapsulation: Sendable {
    /// The shared secret, held in CryptoKit's locked, self-zeroing storage.
    public let sharedSecret: SymmetricKey
    /// The ciphertext to transmit to the holder of the private key.
    public let ciphertext: Data

    public init(sharedSecret: SymmetricKey, ciphertext: Data) {
        self.sharedSecret = sharedSecret
        self.ciphertext = ciphertext
    }
}

@available(iOS 17.0, macOS 14.0, tvOS 17.0, watchOS 10.0, *)
extension Encapsulation {
    /// The same values as CryptoKit's `KEM.EncapsulationResult`.
    public var kemResult: KEM.EncapsulationResult {
        KEM.EncapsulationResult(sharedSecret: sharedSecret, encapsulated: ciphertext)
    }
}

public enum KEMError: Error, LocalizedError {
    case invalidKeyLength
    case invalidCiphertextLength

    public var errorDescription: String? {
        switch self {
        case .invalidKeyLength: return "Invalid key length for this parameter set"
        case .invalidCiphertextLength: return "Invalid ciphertext length for this parameter set"
        }
    }
}

// MARK: - ML-KEM

/// Namespace for the post-quantum KEM families.
///
/// These deliberately mirror the names CryptoKit uses from iOS 26 —
/// `MLKEM768`, `MLKEM1024`, `XWingMLKEM768X25519` — but sit under `PQ` so that
/// a file importing both modules never has to disambiguate. Migrating to the
/// OS implementation later is a matter of dropping the `PQ.` prefix.
public enum PQ {

    /// ML-KEM-768 (FIPS 203), Category 3.
    ///
    /// Wire-compatible with `CryptoKit.MLKEM768`: keys and ciphertexts cross
    /// between the two implementations.
    public enum MLKEM768: Sendable {}

    /// ML-KEM-1024 (FIPS 203), Category 5.
    ///
    /// Wire-compatible with `CryptoKit.MLKEM1024`.
    public enum MLKEM1024: Sendable {}

    /// X-Wing (draft-connolly-cfrg-xwing-kem-10), combining ML-KEM-768 and X25519.
    ///
    /// Equivalent to `CryptoKit.XWingMLKEM768X25519`.
    public enum XWing: Sendable {}

    /// A non-standard hybrid of ML-KEM-1024 and X25519 with a SHA-512 combiner.
    ///
    /// Has no specification and will not interoperate with other
    /// implementations. Prefer ``PQ/XWing``.
    public enum HybridMLKEM1024X25519: Sendable {}
}

// MARK: - Key types

/// Shared implementation detail for the four KEM families above. Each family
/// supplies its own sizes and forwards to the primitive layer.
///
/// Public only because the generic key types below expose public members
/// constrained by it. It is not API: do not conform your own types to it, and
/// do not rely on its requirements across versions.
public protocol _KEMFamily: Sendable {
    static var _publicKeyByteCount: Int { get }
    static var _privateKeyByteCount: Int { get }
    static var _ciphertextByteCount: Int { get }

    static func _validate(publicKey: [UInt8]) throws
    static func _generate() throws -> (publicKey: [UInt8], privateKey: [UInt8])
    static func _publicKey(forPrivateKey privateKey: [UInt8]) throws -> [UInt8]
    static func _encapsulate(publicKey: [UInt8]) throws -> (sharedSecret: [UInt8], ciphertext: [UInt8])
    static func _decapsulate(ciphertext: [UInt8], privateKey: [UInt8]) throws -> [UInt8]
}

extension PQ.MLKEM768: _KEMFamily {
    public static var _publicKeyByteCount: Int { MLKEM.Mode.kem768.publicKeyLength }
    public static var _privateKeyByteCount: Int { MLKEM.Mode.kem768.privateKeyLength }
    public static var _ciphertextByteCount: Int { MLKEM.Mode.kem768.ciphertextLength }

    public static func _validate(publicKey: [UInt8]) throws {
        try MLKEM.validate(publicKey: publicKey, mode: .kem768)
    }
    public static func _generate() throws -> (publicKey: [UInt8], privateKey: [UInt8]) {
        let pair = try MLKEM.generateKeyPair(mode: .kem768)
        return (pair.publicKey, pair.privateKey)
    }
    public static func _publicKey(forPrivateKey privateKey: [UInt8]) throws -> [UInt8] {
        try MLKEM.embeddedPublicKey(inPrivateKey: privateKey, mode: .kem768)
    }
    public static func _encapsulate(publicKey: [UInt8]) throws -> (sharedSecret: [UInt8], ciphertext: [UInt8]) {
        try MLKEM.encapsulate(publicKey: publicKey, mode: .kem768)
    }
    public static func _decapsulate(ciphertext: [UInt8], privateKey: [UInt8]) throws -> [UInt8] {
        try MLKEM.decapsulate(ciphertext: ciphertext, privateKey: privateKey, mode: .kem768)
    }
}

extension PQ.MLKEM1024: _KEMFamily {
    public static var _publicKeyByteCount: Int { MLKEM.Mode.kem1024.publicKeyLength }
    public static var _privateKeyByteCount: Int { MLKEM.Mode.kem1024.privateKeyLength }
    public static var _ciphertextByteCount: Int { MLKEM.Mode.kem1024.ciphertextLength }

    public static func _validate(publicKey: [UInt8]) throws {
        try MLKEM.validate(publicKey: publicKey, mode: .kem1024)
    }
    public static func _generate() throws -> (publicKey: [UInt8], privateKey: [UInt8]) {
        let pair = try MLKEM.generateKeyPair(mode: .kem1024)
        return (pair.publicKey, pair.privateKey)
    }
    public static func _publicKey(forPrivateKey privateKey: [UInt8]) throws -> [UInt8] {
        try MLKEM.embeddedPublicKey(inPrivateKey: privateKey, mode: .kem1024)
    }
    public static func _encapsulate(publicKey: [UInt8]) throws -> (sharedSecret: [UInt8], ciphertext: [UInt8]) {
        try MLKEM.encapsulate(publicKey: publicKey, mode: .kem1024)
    }
    public static func _decapsulate(ciphertext: [UInt8], privateKey: [UInt8]) throws -> [UInt8] {
        try MLKEM.decapsulate(ciphertext: ciphertext, privateKey: privateKey, mode: .kem1024)
    }
}

extension PQ.XWing: _KEMFamily {
    public static var _publicKeyByteCount: Int { XWingX25519.publicKeyLength }
    public static var _privateKeyByteCount: Int { XWingX25519.privateKeyLength }
    public static var _ciphertextByteCount: Int { XWingX25519.ciphertextLength }

    public static func _validate(publicKey: [UInt8]) throws {
        try MLKEM.validate(publicKey: Array(publicKey[0..<XWingX25519.mlkemPublicKeyLength]), mode: .kem768)
    }
    public static func _generate() throws -> (publicKey: [UInt8], privateKey: [UInt8]) {
        let pair = try XWingX25519.generateKeyPair()
        return (pair.publicKey, pair.privateKey)
    }
    public static func _publicKey(forPrivateKey privateKey: [UInt8]) throws -> [UInt8] {
        try XWingX25519.generateKeyPair(seed: privateKey).publicKey
    }
    public static func _encapsulate(publicKey: [UInt8]) throws -> (sharedSecret: [UInt8], ciphertext: [UInt8]) {
        try XWingX25519.encapsulate(publicKey: publicKey)
    }
    public static func _decapsulate(ciphertext: [UInt8], privateKey: [UInt8]) throws -> [UInt8] {
        try XWingX25519.decapsulate(ciphertext: ciphertext, privateKey: privateKey)
    }
}

extension PQ.HybridMLKEM1024X25519: _KEMFamily {
    public static var _publicKeyByteCount: Int { HybridKEM1024.publicKeyLength }
    public static var _privateKeyByteCount: Int { HybridKEM1024.privateKeyLength }
    public static var _ciphertextByteCount: Int { HybridKEM1024.ciphertextLength }

    public static func _validate(publicKey: [UInt8]) throws {
        try MLKEM.validate(publicKey: Array(publicKey[0..<HybridKEM1024.mlkemPublicKeyLength]), mode: .kem1024)
    }
    public static func _generate() throws -> (publicKey: [UInt8], privateKey: [UInt8]) {
        let pair = try HybridKEM1024.generateKeyPair()
        return (pair.publicKey, pair.privateKey)
    }
    public static func _publicKey(forPrivateKey privateKey: [UInt8]) throws -> [UInt8] {
        try HybridKEM1024.embeddedPublicKey(inPrivateKey: privateKey)
    }
    public static func _encapsulate(publicKey: [UInt8]) throws -> (sharedSecret: [UInt8], ciphertext: [UInt8]) {
        try HybridKEM1024.encapsulate(publicKey: publicKey)
    }
    public static func _decapsulate(ciphertext: [UInt8], privateKey: [UInt8]) throws -> [UInt8] {
        try HybridKEM1024.decapsulate(ciphertext: ciphertext, privateKey: privateKey)
    }
}

/// Generates the `PublicKey` and `PrivateKey` pair for one KEM family.
///
/// Declared as a macro-free generic so all four families share one
/// implementation while still presenting distinct, non-interchangeable types.
public struct KEMPublicKeyOf<Family: _KEMFamily>: Sendable, Equatable {
    /// The encoded key, safe to transmit and store in the clear.
    public let rawRepresentation: Data

    fileprivate init(unchecked rawRepresentation: Data) {
        self.rawRepresentation = rawRepresentation
    }
}

public struct KEMPrivateKeyOf<Family: _KEMFamily>: Sendable {
    fileprivate let storage: SecretBytes
    fileprivate let cachedPublicKey: Data

    fileprivate init(storage: SecretBytes, publicKey: Data) {
        self.storage = storage
        self.cachedPublicKey = publicKey
    }
}

extension PQ.MLKEM768 {
    public typealias PublicKey = KEMPublicKeyOf<PQ.MLKEM768>
    public typealias PrivateKey = KEMPrivateKeyOf<PQ.MLKEM768>
}

extension PQ.MLKEM1024 {
    public typealias PublicKey = KEMPublicKeyOf<PQ.MLKEM1024>
    public typealias PrivateKey = KEMPrivateKeyOf<PQ.MLKEM1024>
}

extension PQ.XWing {
    public typealias PublicKey = KEMPublicKeyOf<PQ.XWing>
    public typealias PrivateKey = KEMPrivateKeyOf<PQ.XWing>
}

extension PQ.HybridMLKEM1024X25519 {
    public typealias PublicKey = KEMPublicKeyOf<PQ.HybridMLKEM1024X25519>
    public typealias PrivateKey = KEMPrivateKeyOf<PQ.HybridMLKEM1024X25519>
}

// MARK: - Public key behaviour

extension KEMPublicKeyOf where Family: _KEMFamily {
    /// The encoded size of a public key for this family.
    public static var byteCount: Int { Family._publicKeyByteCount }

    /// Decodes and validates an encoded public key.
    ///
    /// For ML-KEM based families this performs the FIPS 203 §7.2 modulus check,
    /// so a malformed key is rejected here rather than silently accepted.
    public init<D: DataProtocol>(rawRepresentation: D) throws {
        let bytes = Array(rawRepresentation)
        guard bytes.count == Family._publicKeyByteCount else {
            throw KEMError.invalidKeyLength
        }
        try Family._validate(publicKey: bytes)
        self.init(unchecked: Data(bytes))
    }

    /// Encapsulates a fresh shared secret against this key.
    ///
    /// On iOS 17 and later, `encapsulate()` returns CryptoKit's
    /// `KEM.EncapsulationResult` instead; both produce the same values.
    public func encapsulateSharedSecret() throws -> Encapsulation {
        var (sharedSecret, ciphertext) = try Family._encapsulate(publicKey: Array(rawRepresentation))
        return Encapsulation(
            sharedSecret: makeSymmetricKey(consuming: &sharedSecret),
            ciphertext: Data(ciphertext)
        )
    }
}

// MARK: - Private key behaviour

extension KEMPrivateKeyOf where Family: _KEMFamily {
    /// The encoded size of a private key for this family.
    ///
    /// For `XWing` this is 32 bytes, because the draft defines the
    /// decapsulation key as a seed.
    public static var byteCount: Int { Family._privateKeyByteCount }

    /// Generates a new key pair from the system random source.
    public init() throws {
        let generated = try Family._generate()
        self.init(storage: SecretBytes(generated.privateKey), publicKey: Data(generated.publicKey))
    }

    /// Restores a private key from its encoded form, recomputing the public key.
    public init<D: DataProtocol>(rawRepresentation: D) throws {
        let bytes = Array(rawRepresentation)
        guard bytes.count == Family._privateKeyByteCount else {
            throw KEMError.invalidKeyLength
        }
        let publicKey = try Family._publicKey(forPrivateKey: bytes)
        self.init(storage: SecretBytes(bytes), publicKey: Data(publicKey))
    }

    /// The matching public key.
    public var publicKey: KEMPublicKeyOf<Family> {
        KEMPublicKeyOf(unchecked: cachedPublicKey)
    }

    /// Yields the encoded private key for storage, without copying it into a
    /// value the caller keeps by default.
    ///
    /// Write it straight to the Keychain inside `body`. Anything retained past
    /// the closure is outside this package's control.
    public func withUnsafeRawRepresentation<T>(_ body: ([UInt8]) throws -> T) rethrows -> T {
        try storage.withBytes(body)
    }

    /// Recovers the shared secret from a ciphertext.
    ///
    /// This is also the witness for CryptoKit's `KEMPrivateKey.decapsulate`.
    public func decapsulate(_ ciphertext: Data) throws -> SymmetricKey {
        guard ciphertext.count == Family._ciphertextByteCount else {
            throw KEMError.invalidCiphertextLength
        }
        var sharedSecret = try storage.withBytes { privateKey in
            try Family._decapsulate(ciphertext: Array(ciphertext), privateKey: privateKey)
        }
        return makeSymmetricKey(consuming: &sharedSecret)
    }
}

// MARK: - CryptoKit KEM conformance

// CryptoKit's KEM protocols arrived in iOS 17, below which the types above are
// still usable through `encapsulateSharedSecret()` and `decapsulate(_:)`.
//
// `encapsulate()` is declared only here, rather than alongside
// `encapsulateSharedSecret()`, because two methods differing solely in return
// type would make unannotated call sites ambiguous.

@available(iOS 17.0, macOS 14.0, tvOS 17.0, watchOS 10.0, *)
extension KEMPublicKeyOf: KEMPublicKey where Family: _KEMFamily {
    public func encapsulate() throws -> KEM.EncapsulationResult {
        try encapsulateSharedSecret().kemResult
    }
}

@available(iOS 17.0, macOS 14.0, tvOS 17.0, watchOS 10.0, *)
extension KEMPrivateKeyOf: KEMPrivateKey where Family: _KEMFamily {
    public static func generate() throws -> Self {
        try Self()
    }
}
