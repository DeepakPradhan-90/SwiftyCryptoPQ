import Foundation
import CryptoKit
import CryptoPQ

// MARK: - Key Derivation Helper
enum KeyDeriver {
    /// Derives a 256-bit AES key using HKDF-SHA256 from input key material.
    static func deriveAES256Key(from sharedSecret: [UInt8], salt: [UInt8], info: [UInt8]) -> SymmetricKey {
        let inputKey = SymmetricKey(data: sharedSecret)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: salt,
            info: info,
            outputByteCount: 32 // 256 bits
        )
    }

    /// Derives a 512-bit Master Secret using HKDF-SHA512 from input key material.
    /// Since standard AES supports up to 256-bit keys, we split this 512-bit master secret into:
    /// - 256-bit AES-GCM encryption key
    /// - 256-bit MAC/HMAC verification key
    static func deriveAndSplit512BitSecret(from sharedSecret: [UInt8], salt: [UInt8], info: [UInt8]) -> (aesKey: SymmetricKey, macKey: SymmetricKey) {
        let inputKey = SymmetricKey(data: sharedSecret)
        let masterSecretBytes = HKDF<SHA512>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: salt,
            info: info,
            outputByteCount: 64 // 512 bits
        ).withUnsafeBytes { Array($0) }

        let aesBytes = Array(masterSecretBytes[0..<32])
        let macBytes = Array(masterSecretBytes[32..<64])

        return (SymmetricKey(data: aesBytes), SymmetricKey(data: macBytes))
    }
}

// MARK: - AEAD Encryption Helper
enum AEADHelper {
    static func encrypt(plaintext: String, using key: SymmetricKey, associatedData: [UInt8]) throws -> (ciphertext: [UInt8], nonce: AES.GCM.Nonce, tag: [UInt8]) {
        let data = Data(plaintext.utf8)
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(data, using: key, nonce: nonce, authenticating: associatedData)
        return (Array(sealedBox.ciphertext), sealedBox.nonce, Array(sealedBox.tag))
    }

    static func decrypt(ciphertext: [UInt8], using key: SymmetricKey, nonce: AES.GCM.Nonce, tag: [UInt8], associatedData: [UInt8]) throws -> String {
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        let decryptedData = try AES.GCM.open(sealedBox, using: key, authenticating: associatedData)
        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw NSError(domain: "AEADHelper", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to decode decrypted string"])
        }
        return decryptedString
    }
}

// MARK: - Execution Main Entry
func runDemo() {
    print("================================================================================")
    print("     SwiftyBoringSSL - Post-Quantum Hybrid Cryptography Demonstration")
    print("================================================================================")

    let secretMessage = "Confidential: Meet at midnight under the post-quantum umbrella."
    let salt = [UInt8]("SwiftyBoringSSL-KDF-Salt".utf8)
    let info = [UInt8]("Session-Keys-Binding-Info".utf8)
    let associatedData = [UInt8]("AEAD-Context-Binding-v1".utf8)

    print("\n[+] Plaintext to encrypt: '\(secretMessage)'")

    do {
        // -------------------------------------------------------------------------
        // 1. Digital Signature Key Generation (ML-DSA-65)
        // -------------------------------------------------------------------------
        print("\n--- [Phase 1: Digital Signatures Setup (ML-DSA-65)] ---")
        let signingKeyPair = try MLDSA.generateKeyPair(mode: .dsa65)
        print("✔ ML-DSA-65 signing keypair successfully generated.")
        print("  - Public Key length:  \(signingKeyPair.publicKey.count) bytes")
        print("  - Private Key length: \(signingKeyPair.privateKey.count) bytes")

        // -------------------------------------------------------------------------
        // 2. KEM Combinations & Hybrid Shared Secret Agreements
        // -------------------------------------------------------------------------
        print("\n--- [Phase 2: Hybrid Key Agreement Configurations] ---")

        // COMBINATION A: X-Wing Hybrid KEM (ML-KEM-768 + X25519) [Standard CFRG Hybrid]
        print("\n[A] Configuration: X-Wing Hybrid KEM (ML-KEM-768 + X25519)")
        let receiverXWingKeys = try XWingX25519.generateKeyPair()
        let (xwingSS, xwingCt) = try XWingX25519.encapsulate(publicKey: receiverXWingKeys.publicKey)
        let xwingDecSS = try XWingX25519.decapsulate(ciphertext: xwingCt, privateKey: receiverXWingKeys.privateKey)
        XCTAssert(xwingSS == xwingDecSS, "X-Wing decapsulation failed")
        print("✔ Shared secret agreed via standard X-Wing (32 bytes).")

        // COMBINATION B: Hybrid KEM 1024 (ML-KEM-1024 + X25519) [Custom Maximum Strength]
        print("\n[B] Configuration: Custom Hybrid KEM (ML-KEM-1024 + X25519)")
        let receiver1024Keys = try HybridKEM1024.generateKeyPair()
        let (hybrid1024SS, hybrid1024Ct) = try HybridKEM1024.encapsulate(publicKey: receiver1024Keys.publicKey)
        let hybrid1024DecSS = try HybridKEM1024.decapsulate(ciphertext: hybrid1024Ct, privateKey: receiver1024Keys.privateKey)
        XCTAssert(hybrid1024SS == hybrid1024DecSS, "Hybrid-1024 decapsulation failed")
        print("✔ Shared secret agreed via Custom Hybrid KEM 1024 (64 bytes).")

        // COMBINATION C: Classical-only X25519 Key Agreement
        print("\n[C] Configuration: Classical Curve25519 Key Exchange")
        let aliceKeys = try X25519.generateKeyPair()
        let bobKeys = try X25519.generateKeyPair()
        _ = try X25519.keyExchange(privateKey: aliceKeys.privateKey, peerPublicKey: bobKeys.publicKey)
        print("✔ Shared secret agreed via standard Curve25519 (32 bytes).")


        // -------------------------------------------------------------------------
        // 3. Key Derivation & AEAD (AES-GCM) + ML-DSA Authentication Pipeline
        // -------------------------------------------------------------------------
        print("\n--- [Phase 3: Key Derivation & Encryption Pipeline] ---")

        // Pipeline 1: X-Wing Shared Secret -> Deriving 256-bit AES Key
        print("\n[1] Deriving 256-bit AES Key from X-Wing Shared Secret:")
        let aes256Key = KeyDeriver.deriveAES256Key(from: xwingSS, salt: salt, info: info)
        print("✔ 256-bit symmetric key derived via HKDF-SHA256.")

        // Encrypt with AES-GCM
        let (ct, nonce, tag) = try AEADHelper.encrypt(plaintext: secretMessage, using: aes256Key, associatedData: associatedData)
        print("✔ Authenticated Encryption (AES-256-GCM) complete.")
        print("  - Ciphertext count: \(ct.count) bytes")
        print("  - Authentication tag: \(tag.count) bytes")

        // Authenticate Ciphertext using post-quantum signature (ML-DSA-65)
        print("\n[2] Authenticating Ciphertext via ML-DSA-65 Signature:")
        let signature = try MLDSA.sign(message: ct, privateKey: signingKeyPair.privateKey)
        print("✔ Ciphertext signed successfully.")
        print("  - Signature size: \(signature.count) bytes")

        // Verification & Decryption of Pipeline 1
        print("\n[3] Verifying and Decrypting ciphertext at Bob's side:")
        let isSigValid = try MLDSA.verify(message: ct, signature: signature, publicKey: signingKeyPair.publicKey)
        print("  - ML-DSA Signature verified successfully: \(isSigValid)")
        XCTAssert(isSigValid, "Signature verification failed")

        let decryptedText = try AEADHelper.decrypt(ciphertext: ct, using: aes256Key, nonce: nonce, tag: tag, associatedData: associatedData)
        print("✔ Decrypted payload matches original: '\(decryptedText)'")


        // Pipeline 2: Custom Hybrid 1024 -> Deriving 512-bit Master Secret (Split into AES & MAC keys)
        print("\n[4] Deriving 512-bit Master Secret from Custom Hybrid 1024:")
        let (aesKey, _) = KeyDeriver.deriveAndSplit512BitSecret(from: hybrid1024SS, salt: salt, info: info)
        print("✔ Derived 512-bit master secret via HKDF-SHA512.")
        print("  - Portions split into: 256-bit AES Key & 256-bit MAC Verification Key")

        // Encrypt with AES-GCM using derived portion
        let (ct2, nonce2, tag2) = try AEADHelper.encrypt(plaintext: "Second Layer: \(secretMessage)", using: aesKey, associatedData: associatedData)
        print("✔ Authenticated Encryption of second layer complete.")

        let decryptedText2 = try AEADHelper.decrypt(ciphertext: ct2, using: aesKey, nonce: nonce2, tag: tag2, associatedData: associatedData)
        print("✔ Decrypted second layer payload: '\(decryptedText2)'")

        print("\n================================================================================")
        print("  [SUCCESS] All post-quantum and hybrid cryptographic pipelines executed flawlessly!")
        print("================================================================================")

    } catch {
        print("\n❌ Error encountered during cryptographic demo execution: \(error.localizedDescription)")
    }
}

// Custom simple assertion helper to avoid crash/test failures in executable
func XCTAssert(_ condition: Bool, _ message: String) {
    if !condition {
        print("Assertion Failed: \(message)")
        exit(1)
    }
}

runDemo()
