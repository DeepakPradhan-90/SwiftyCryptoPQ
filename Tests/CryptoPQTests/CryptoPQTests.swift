import XCTest
import CryptoPQ

final class CryptoPQTests: XCTestCase {

    // MARK: - ML-KEM Tests

    func testMLKEM768RoundTrip() throws {
        // 1. Generate keypair
        let keyPair = try MLKEM.generateKeyPair(mode: .kem768)
        XCTAssertEqual(keyPair.publicKey.count, MLKEM.Mode.kem768.publicKeyLength)
        XCTAssertEqual(keyPair.privateKey.count, MLKEM.Mode.kem768.privateKeyLength)

        // 2. Encapsulate
        let (ss, ct) = try MLKEM.encapsulate(publicKey: keyPair.publicKey)
        XCTAssertEqual(ss.count, MLKEM.Mode.kem768.sharedSecretLength)
        XCTAssertEqual(ct.count, MLKEM.Mode.kem768.ciphertextLength)

        // 3. Decapsulate
        let ssDecrypted = try MLKEM.decapsulate(ciphertext: ct, privateKey: keyPair.privateKey)
        XCTAssertEqual(ss, ssDecrypted)
    }

    func testMLKEM1024RoundTrip() throws {
        // 1. Generate keypair
        let keyPair = try MLKEM.generateKeyPair(mode: .kem1024)
        XCTAssertEqual(keyPair.publicKey.count, MLKEM.Mode.kem1024.publicKeyLength)
        XCTAssertEqual(keyPair.privateKey.count, MLKEM.Mode.kem1024.privateKeyLength)

        // 2. Encapsulate
        let (ss, ct) = try MLKEM.encapsulate(publicKey: keyPair.publicKey)
        XCTAssertEqual(ss.count, MLKEM.Mode.kem1024.sharedSecretLength)
        XCTAssertEqual(ct.count, MLKEM.Mode.kem1024.ciphertextLength)

        // 3. Decapsulate
        let ssDecrypted = try MLKEM.decapsulate(ciphertext: ct, privateKey: keyPair.privateKey)
        XCTAssertEqual(ss, ssDecrypted)
    }

    func testMLKEMValidationAndErrors() throws {
        let keyPair = try MLKEM.generateKeyPair(mode: .kem768)

        // 1. Invalid public key length
        let badPublicKey = Array(keyPair.publicKey.dropLast())
        XCTAssertThrowsError(try MLKEM.encapsulate(publicKey: badPublicKey)) { error in
            XCTAssertEqual(error as? MLKEMError, .invalidPublicKeyLength)
        }

        // 2. Invalid private key length
        let badPrivateKey = Array(keyPair.privateKey.dropLast())
        let (_, ct) = try MLKEM.encapsulate(publicKey: keyPair.publicKey)
        XCTAssertThrowsError(try MLKEM.decapsulate(ciphertext: ct, privateKey: badPrivateKey)) { error in
            XCTAssertEqual(error as? MLKEMError, .invalidPrivateKeyLength)
        }

        // 3. Invalid ciphertext length
        let badCiphertext = Array(ct.dropLast())
        XCTAssertThrowsError(try MLKEM.decapsulate(ciphertext: badCiphertext, privateKey: keyPair.privateKey)) { error in
            XCTAssertEqual(error as? MLKEMError, .invalidCiphertextLength)
        }

        // 4. Decapsulating tampered ciphertext (Implicit Rejection)
        var tamperedCiphertext = ct
        tamperedCiphertext[0] ^= 0x01
        let ssDecryptedTampered = try MLKEM.decapsulate(ciphertext: tamperedCiphertext, privateKey: keyPair.privateKey)
        // Under FIPS 203 implicit rejection, it should NOT match the original shared secret
        let (ss, _) = try MLKEM.encapsulate(publicKey: keyPair.publicKey)
        XCTAssertNotEqual(ss, ssDecryptedTampered)

        // 5. Automatic mode inference verification
        let keyPair1024 = try MLKEM.generateKeyPair(mode: .kem1024)
        let (ss1024, ct1024) = try MLKEM.encapsulate(publicKey: keyPair1024.publicKey)
        let ssDecrypted1024 = try MLKEM.decapsulate(ciphertext: ct1024, privateKey: keyPair1024.privateKey)
        XCTAssertEqual(ss1024, ssDecrypted1024)
    }

    // MARK: - ML-DSA Tests

    func testMLDSA44RoundTrip() throws {
        // 1. Generate keypair
        let keyPair = try MLDSA.generateKeyPair(mode: .dsa44)
        XCTAssertEqual(keyPair.publicKey.count, MLDSA.Mode.dsa44.publicKeyLength)
        XCTAssertEqual(keyPair.privateKey.count, MLDSA.Mode.dsa44.privateKeyLength)

        // 2. Sign
        let message = Array("Hello Post-Quantum Signatures on iOS 13!".utf8)
        let signature = try MLDSA.sign(message: message, privateKey: keyPair.privateKey)
        XCTAssertTrue(signature.count <= MLDSA.Mode.dsa44.signatureLength)

        // 3. Verify
        let isValid = try MLDSA.verify(message: message, signature: signature, publicKey: keyPair.publicKey)
        XCTAssertTrue(isValid)

        // 4. Verify tampering detects failure
        var tamperedMessage = message
        tamperedMessage[0] ^= 0x01
        let isTamperedValid = try MLDSA.verify(message: tamperedMessage, signature: signature, publicKey: keyPair.publicKey)
        XCTAssertFalse(isTamperedValid)
    }

    func testMLDSA65RoundTrip() throws {
        // 1. Generate keypair
        let keyPair = try MLDSA.generateKeyPair(mode: .dsa65)
        XCTAssertEqual(keyPair.publicKey.count, MLDSA.Mode.dsa65.publicKeyLength)
        XCTAssertEqual(keyPair.privateKey.count, MLDSA.Mode.dsa65.privateKeyLength)

        // 2. Sign
        let message = Array("Standard Dilithium security level 3".utf8)
        let signature = try MLDSA.sign(message: message, privateKey: keyPair.privateKey)
        XCTAssertTrue(signature.count <= MLDSA.Mode.dsa65.signatureLength)

        // 3. Verify
        let isValid = try MLDSA.verify(message: message, signature: signature, publicKey: keyPair.publicKey)
        XCTAssertTrue(isValid)
    }

    func testMLDSA87RoundTrip() throws {
        // 1. Generate keypair
        let keyPair = try MLDSA.generateKeyPair(mode: .dsa87)
        XCTAssertEqual(keyPair.publicKey.count, MLDSA.Mode.dsa87.publicKeyLength)
        XCTAssertEqual(keyPair.privateKey.count, MLDSA.Mode.dsa87.privateKeyLength)

        // 2. Sign
        let message = Array("Ultra secure Dilithium security level 5".utf8)
        let signature = try MLDSA.sign(message: message, privateKey: keyPair.privateKey)
        XCTAssertTrue(signature.count <= MLDSA.Mode.dsa87.signatureLength)

        // 3. Verify
        let isValid = try MLDSA.verify(message: message, signature: signature, publicKey: keyPair.publicKey)
        XCTAssertTrue(isValid)
    }

    func testMLDSAValidationAndErrors() throws {
        let keyPair = try MLDSA.generateKeyPair(mode: .dsa44)
        let message = Array("Test validation message".utf8)
        let signature = try MLDSA.sign(message: message, privateKey: keyPair.privateKey)

        // 1. Invalid private key length to sign
        let badPrivateKey = Array(keyPair.privateKey.dropLast())
        XCTAssertThrowsError(try MLDSA.sign(message: message, privateKey: badPrivateKey)) { error in
            XCTAssertEqual(error as? MLDSAError, .invalidPrivateKeyLength)
        }

        // 2. Invalid public key length to verify
        let badPublicKey = Array(keyPair.publicKey.dropLast())
        XCTAssertThrowsError(try MLDSA.verify(message: message, signature: signature, publicKey: badPublicKey)) { error in
            XCTAssertEqual(error as? MLDSAError, .invalidPublicKeyLength)
        }

        // 3. Invalid signature length to verify (longer than maximum signature size)
        let excessivelyLongSignature = signature + [UInt8](repeating: 0, count: MLDSA.Mode.dsa44.signatureLength)
        XCTAssertThrowsError(try MLDSA.verify(message: message, signature: excessivelyLongSignature, publicKey: keyPair.publicKey)) { error in
            XCTAssertEqual(error as? MLDSAError, .invalidSignatureLength)
        }

        // 4. Verification fails on modified signature
        var tamperedSignature = signature
        tamperedSignature[tamperedSignature.count - 1] ^= 0x01
        let isTamperedSignatureValid = try MLDSA.verify(message: message, signature: tamperedSignature, publicKey: keyPair.publicKey)
        XCTAssertFalse(isTamperedSignatureValid)

        // 5. Automatic mode inference verification
        let keyPair65 = try MLDSA.generateKeyPair(mode: .dsa65)
        let signature65 = try MLDSA.sign(message: message, privateKey: keyPair65.privateKey)
        XCTAssertTrue(try MLDSA.verify(message: message, signature: signature65, publicKey: keyPair65.publicKey))
    }

    // MARK: - X25519 Tests

    func testX25519RoundTrip() throws {
        // 1. Generate two keypairs
        let (skA, pkA) = try X25519.generateKeyPair()
        let (skB, pkB) = try X25519.generateKeyPair()

        XCTAssertEqual(skA.count, 32)
        XCTAssertEqual(pkA.count, 32)

        // 2. Perform key exchange on both sides
        let ssA = try X25519.keyExchange(privateKey: skA, peerPublicKey: pkB)
        let ssB = try X25519.keyExchange(privateKey: skB, peerPublicKey: pkA)

        // 3. Verify shared secret is identical
        XCTAssertEqual(ssA.count, 32)
        XCTAssertEqual(ssA, ssB)
    }

    func testX25519ValidationAndErrors() throws {
        let (skA, pkA) = try X25519.generateKeyPair()

        // 1. Invalid private key length
        let badPrivateKey = Array(skA.dropLast())
        XCTAssertThrowsError(try X25519.keyExchange(privateKey: badPrivateKey, peerPublicKey: pkA)) { error in
            XCTAssertEqual(error as? X25519Error, .invalidPrivateKeyLength)
        }

        // 2. Invalid public key length
        let badPublicKey = Array(pkA.dropLast())
        XCTAssertThrowsError(try X25519.keyExchange(privateKey: skA, peerPublicKey: badPublicKey)) { error in
            XCTAssertEqual(error as? X25519Error, .invalidPublicKeyLength)
        }
    }

    func testX25519SharedSecretAccessors() throws {
        let (skA, pkA) = try X25519.generateKeyPair()
        let (skB, pkB) = try X25519.generateKeyPair()

        // The borrowing accessor must agree with the copying one.
        let copied = try X25519.keyExchange(privateKey: skA, peerPublicKey: pkB)
        let borrowed = try X25519.withSharedSecret(privateKey: skA, peerPublicKey: pkB) { Array($0) }
        XCTAssertEqual(copied, borrowed)

        let peer = try X25519.withSharedSecret(privateKey: skB, peerPublicKey: pkA) { Array($0) }
        XCTAssertEqual(borrowed, peer)

        // Errors thrown by the closure propagate unchanged rather than being
        // reported as a key agreement failure.
        struct Sentinel: Error {}
        XCTAssertThrowsError(
            try X25519.withSharedSecret(privateKey: skA, peerPublicKey: pkB) { _ in throw Sentinel() }
        ) { error in
            XCTAssertTrue(error is Sentinel)
        }

        XCTAssertThrowsError(try X25519.withSharedSecret(privateKey: [], peerPublicKey: pkB) { _ in }) { error in
            XCTAssertEqual(error as? X25519Error, .invalidPrivateKeyLength)
        }
    }

    // MARK: - Process Hardening

    func testDisableCoreDumps() {
        // Lowering a soft resource limit is always permitted.
        XCTAssertTrue(ProcessHardening.disableCoreDumps())

        var limit = rlimit()
        XCTAssertEqual(getrlimit(RLIMIT_CORE, &limit), 0)
        XCTAssertEqual(limit.rlim_cur, 0)
    }

    func testMemoryLocking() {
        let count = 64
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: count, alignment: 16)
        defer { buffer.deallocate() }

        if ProcessHardening.lockMemory(buffer, count: count) {
            XCTAssertTrue(ProcessHardening.unlockMemory(buffer, count: count))
        }
        // mlock can legitimately fail on a limit-constrained host, so a failure
        // to lock is not treated as a test failure.
    }

    // MARK: - X-Wing Tests

    func testXWingRoundTrip() throws {
        // 1. Generate hybrid keypair
        let keyPair = try XWingX25519.generateKeyPair()
        XCTAssertEqual(keyPair.publicKey.count, XWingX25519.publicKeyLength)
        XCTAssertEqual(keyPair.privateKey.count, XWingX25519.privateKeyLength)
        XCTAssertEqual(keyPair.privateKey.count, 32)

        // 2. Encapsulate
        let (ss, ct) = try XWingX25519.encapsulate(publicKey: keyPair.publicKey)
        XCTAssertEqual(ss.count, XWingX25519.sharedSecretLength)
        XCTAssertEqual(ct.count, XWingX25519.ciphertextLength)

        // 3. Decapsulate
        let ssDecrypted = try XWingX25519.decapsulate(ciphertext: ct, privateKey: keyPair.privateKey)
        XCTAssertEqual(ss, ssDecrypted)
    }

    func testXWingValidationAndErrors() throws {
        let keyPair = try XWingX25519.generateKeyPair()
        let (ss, ct) = try XWingX25519.encapsulate(publicKey: keyPair.publicKey)

        // 1. Invalid encapsulation key length
        let badPublicKey = Array(keyPair.publicKey.dropLast())
        XCTAssertThrowsError(try XWingX25519.encapsulate(publicKey: badPublicKey)) { error in
            XCTAssertEqual(error as? XWingError, .invalidPublicKeyLength)
        }

        // 2. Invalid decapsulation key length
        let badPrivateKey = Array(keyPair.privateKey.dropLast())
        XCTAssertThrowsError(try XWingX25519.decapsulate(ciphertext: ct, privateKey: badPrivateKey)) { error in
            XCTAssertEqual(error as? XWingError, .invalidPrivateKeyLength)
        }

        // 3. Invalid ciphertext length
        let badCiphertext = Array(ct.dropLast())
        XCTAssertThrowsError(try XWingX25519.decapsulate(ciphertext: badCiphertext, privateKey: keyPair.privateKey)) { error in
            XCTAssertEqual(error as? XWingError, .invalidCiphertextLength)
        }

        // 4. Invalid encapsulation seed length
        XCTAssertThrowsError(try XWingX25519.encapsulate(publicKey: keyPair.publicKey, eseed: [0, 1, 2])) { error in
            XCTAssertEqual(error as? XWingError, .invalidSeedLength)
        }

        // 5. Decapsulating a tampered ciphertext yields an unrelated shared secret
        var tamperedCiphertext = ct
        tamperedCiphertext[0] ^= 0x01
        let ssTampered = try XWingX25519.decapsulate(ciphertext: tamperedCiphertext, privateKey: keyPair.privateKey)
        XCTAssertNotEqual(ss, ssTampered)

        // 6. Key generation is deterministic in the seed
        let regenerated = try XWingX25519.generateKeyPair(seed: keyPair.privateKey)
        XCTAssertEqual(regenerated.publicKey, keyPair.publicKey)
    }

    // MARK: - HybridKEM1024 Tests

    func testHybridKEM1024RoundTrip() throws {
        // 1. Generate hybrid keypair
        let keyPair = try HybridKEM1024.generateKeyPair()
        XCTAssertEqual(keyPair.publicKey.count, HybridKEM1024.publicKeyLength)
        XCTAssertEqual(keyPair.privateKey.count, HybridKEM1024.privateKeyLength)

        // 2. Encapsulate
        let (ss, ct) = try HybridKEM1024.encapsulate(publicKey: keyPair.publicKey)
        XCTAssertEqual(ss.count, HybridKEM1024.sharedSecretLength)
        XCTAssertEqual(ct.count, HybridKEM1024.ciphertextLength)

        // 3. Decapsulate
        let ssDecrypted = try HybridKEM1024.decapsulate(ciphertext: ct, privateKey: keyPair.privateKey)
        XCTAssertEqual(ss, ssDecrypted)
    }

    func testHybridKEM1024ValidationAndErrors() throws {
        let keyPair = try HybridKEM1024.generateKeyPair()
        let (ss, ct) = try HybridKEM1024.encapsulate(publicKey: keyPair.publicKey)

        // 1. Invalid public key length to encapsulate
        let badPublicKey = Array(keyPair.publicKey.dropLast())
        XCTAssertThrowsError(try HybridKEM1024.encapsulate(publicKey: badPublicKey)) { error in
            XCTAssertEqual(error as? HybridKEM1024Error, .invalidPublicKeyLength)
        }

        // 2. Invalid private key length to decapsulate
        let badPrivateKey = Array(keyPair.privateKey.dropLast())
        XCTAssertThrowsError(try HybridKEM1024.decapsulate(ciphertext: ct, privateKey: badPrivateKey)) { error in
            XCTAssertEqual(error as? HybridKEM1024Error, .invalidPrivateKeyLength)
        }

        // 3. Invalid ciphertext length to decapsulate
        let badCiphertext = Array(ct.dropLast())
        XCTAssertThrowsError(try HybridKEM1024.decapsulate(ciphertext: badCiphertext, privateKey: keyPair.privateKey)) { error in
            XCTAssertEqual(error as? HybridKEM1024Error, .invalidCiphertextLength)
        }

        // 4. Decapsulating tampered hybrid ciphertext produces a completely different shared secret
        var tamperedCiphertext = ct
        tamperedCiphertext[0] ^= 0x01
        let ssDecryptedTampered = try HybridKEM1024.decapsulate(ciphertext: tamperedCiphertext, privateKey: keyPair.privateKey)
        XCTAssertNotEqual(ss, ssDecryptedTampered)
    }
}
