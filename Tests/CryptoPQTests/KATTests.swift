import XCTest
@testable import CryptoPQ

/// Known-answer tests against published vectors.
///
/// `Vectors/acvp.json` is a subset of the NIST ACVP server's
/// `internalProjection.json` files for ML-KEM (FIPS 203) and ML-DSA (FIPS 204).
/// `Vectors/xwing.json` holds the Appendix C vectors from
/// draft-connolly-cfrg-xwing-kem-10.
///
/// Unlike the round-trip tests, these catch errors that are self-consistent
/// across encapsulation and decapsulation.
final class KATTests: XCTestCase {

    // MARK: - Loading

    private struct ACVPVectors: Decodable {
        struct MLKEMKeyGen: Decodable {
            let parameterSet: String
            let d: String, z: String, ek: String, dk: String
        }
        struct MLKEMEncap: Decodable {
            let parameterSet: String
            let ek: String, m: String, c: String, k: String
        }
        struct MLKEMDecap: Decodable {
            let parameterSet: String
            let dk: String, c: String, k: String
        }
        struct MLKEMEncapKeyCheck: Decodable {
            let parameterSet: String
            let ek: String, valid: Bool, reason: String
        }
        struct MLKEMDecapKeyCheck: Decodable {
            let parameterSet: String
            let dk: String, valid: Bool, reason: String
        }
        struct MLDSASigVer: Decodable {
            let parameterSet: String
            let pk: String, message: String, context: String, signature: String
            let valid: Bool, reason: String
        }

        let mlkemKeyGen: [MLKEMKeyGen]
        let mlkemEncap: [MLKEMEncap]
        let mlkemDecap: [MLKEMDecap]
        let mlkemEncapKeyCheck: [MLKEMEncapKeyCheck]
        let mlkemDecapKeyCheck: [MLKEMDecapKeyCheck]
        let mldsaSigVer: [MLDSASigVer]
    }

    private struct XWingVector: Decodable {
        let seed: String, sk: String, pk: String, eseed: String, ct: String, ss: String
    }

    private static func load<T: Decodable>(_ name: String) throws -> T {
        guard let url = Bundle.module.url(forResource: "Vectors/\(name)", withExtension: "json") else {
            XCTFail("Missing test vector resource \(name).json")
            throw CocoaError(.fileNoSuchFile)
        }
        return try JSONDecoder().decode(T.self, from: Data(contentsOf: url))
    }

    private lazy var acvp: ACVPVectors = try! Self.load("acvp")
    private lazy var xwing: [XWingVector] = try! Self.load("xwing")

    private func bytes(_ hex: String, file: StaticString = #filePath, line: UInt = #line) -> [UInt8] {
        var result = [UInt8]()
        result.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else {
                XCTFail("Malformed hex in vector", file: file, line: line)
                return []
            }
            result.append(byte)
            index = next
        }
        return result
    }

    private func kemMode(_ parameterSet: String) -> MLKEM.Mode? {
        switch parameterSet {
        case "ML-KEM-768": return .kem768
        case "ML-KEM-1024": return .kem1024
        default: return nil
        }
    }

    private func dsaMode(_ parameterSet: String) -> MLDSA.Mode? {
        switch parameterSet {
        case "ML-DSA-44": return .dsa44
        case "ML-DSA-65": return .dsa65
        case "ML-DSA-87": return .dsa87
        default: return nil
        }
    }

    // MARK: - ML-KEM (FIPS 203)

    func testMLKEMKeyGenKAT() throws {
        XCTAssertFalse(acvp.mlkemKeyGen.isEmpty)
        for vector in acvp.mlkemKeyGen {
            guard let mode = kemMode(vector.parameterSet) else { continue }
            let keyPair = try MLKEM.generateKeyPair(mode: mode, seed: bytes(vector.d) + bytes(vector.z))
            XCTAssertEqual(keyPair.publicKey, bytes(vector.ek), "\(vector.parameterSet) ek")
            XCTAssertEqual(keyPair.privateKey, bytes(vector.dk), "\(vector.parameterSet) dk")
        }
    }

    func testMLKEMEncapsulationKAT() throws {
        XCTAssertFalse(acvp.mlkemEncap.isEmpty)
        for vector in acvp.mlkemEncap {
            guard let mode = kemMode(vector.parameterSet) else { continue }
            let (ss, ct) = try MLKEM.encapsulate(publicKey: bytes(vector.ek), mode: mode, randomness: bytes(vector.m))
            XCTAssertEqual(ct, bytes(vector.c), "\(vector.parameterSet) ciphertext")
            XCTAssertEqual(ss, bytes(vector.k), "\(vector.parameterSet) shared secret")
        }
    }

    func testMLKEMDecapsulationKAT() throws {
        XCTAssertFalse(acvp.mlkemDecap.isEmpty)
        for vector in acvp.mlkemDecap {
            guard let mode = kemMode(vector.parameterSet) else { continue }
            let ss = try MLKEM.decapsulate(ciphertext: bytes(vector.c), privateKey: bytes(vector.dk), mode: mode)
            XCTAssertEqual(ss, bytes(vector.k), "\(vector.parameterSet) shared secret")
        }
    }

    /// FIPS 203 §7.2 modulus check.
    func testMLKEMEncapsulationKeyCheckKAT() throws {
        XCTAssertFalse(acvp.mlkemEncapKeyCheck.isEmpty)
        for vector in acvp.mlkemEncapKeyCheck {
            guard let mode = kemMode(vector.parameterSet) else { continue }
            let key = bytes(vector.ek)
            if vector.valid {
                XCTAssertNoThrow(try MLKEM.validate(publicKey: key, mode: mode), vector.reason)
            } else {
                XCTAssertThrowsError(try MLKEM.validate(publicKey: key, mode: mode), vector.reason) { error in
                    XCTAssertEqual(error as? MLKEMError, .malformedPublicKey)
                }
            }
        }
    }

    /// FIPS 203 §7.3 hash check.
    func testMLKEMDecapsulationKeyCheckKAT() throws {
        XCTAssertFalse(acvp.mlkemDecapKeyCheck.isEmpty)
        for vector in acvp.mlkemDecapKeyCheck {
            guard let mode = kemMode(vector.parameterSet) else { continue }
            let key = bytes(vector.dk)
            if vector.valid {
                XCTAssertNoThrow(try MLKEM.validate(privateKey: key, mode: mode), vector.reason)
            } else {
                XCTAssertThrowsError(try MLKEM.validate(privateKey: key, mode: mode), vector.reason) { error in
                    XCTAssertEqual(error as? MLKEMError, .malformedPrivateKey)
                }
            }
        }
    }

    // MARK: - ML-DSA (FIPS 204)

    func testMLDSASignatureVerificationKAT() throws {
        XCTAssertFalse(acvp.mldsaSigVer.isEmpty)
        for vector in acvp.mldsaSigVer {
            guard let mode = dsaMode(vector.parameterSet) else { continue }
            let isValid = try MLDSA.verify(
                message: bytes(vector.message),
                signature: bytes(vector.signature),
                publicKey: bytes(vector.pk),
                mode: mode,
                context: bytes(vector.context)
            )
            XCTAssertEqual(isValid, vector.valid, "\(vector.parameterSet): \(vector.reason)")
        }
    }

    // MARK: - X-Wing (draft-connolly-cfrg-xwing-kem-10)

    func testXWingKAT() throws {
        XCTAssertFalse(xwing.isEmpty)
        for vector in xwing {
            let keyPair = try XWingX25519.generateKeyPair(seed: bytes(vector.seed))
            XCTAssertEqual(keyPair.privateKey, bytes(vector.sk), "decapsulation key")
            XCTAssertEqual(keyPair.publicKey, bytes(vector.pk), "encapsulation key")

            let (ss, ct) = try XWingX25519.encapsulate(publicKey: bytes(vector.pk), eseed: bytes(vector.eseed))
            XCTAssertEqual(ct, bytes(vector.ct), "ciphertext")
            XCTAssertEqual(ss, bytes(vector.ss), "shared secret")

            let decapsulated = try XWingX25519.decapsulate(ciphertext: bytes(vector.ct), privateKey: bytes(vector.sk))
            XCTAssertEqual(decapsulated, bytes(vector.ss), "decapsulated shared secret")
        }
    }
}
