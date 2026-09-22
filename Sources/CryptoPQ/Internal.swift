import Foundation
import CryptoKit
import CryptoPQC

/// FIPS 202 primitives, backed by the vendored reference implementation so that
/// they are available on every supported OS version.
enum FIPS202 {
    static func sha3_256(_ input: [UInt8]) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: 32)
        CryptoPQC.sha3_256(&output, input, input.count)
        return output
    }

    static func shake256(_ input: [UInt8], outputLength: Int) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: outputLength)
        CryptoPQC.shake256(&output, outputLength, input, input.count)
        return output
    }

    /// Incremental SHA3-256, so that inputs made of secret and public parts can
    /// be absorbed in place instead of being concatenated into one buffer that
    /// then has to be wiped.
    ///
    /// The underlying sponge state is heap allocated by `init` and released by
    /// `finalize`, so an instance must always be finalized exactly once. Keep
    /// use linear and non-throwing.
    struct SHA3_256Hasher {
        private var state = sha3_256incctx()

        init() {
            sha3_256_inc_init(&state)
        }

        mutating func absorb(_ bytes: [UInt8]) {
            sha3_256_inc_absorb(&state, bytes, bytes.count)
        }

        mutating func absorb(_ buffer: UnsafeRawBufferPointer) {
            guard let base = buffer.baseAddress else { return }
            sha3_256_inc_absorb(&state, base.assumingMemoryBound(to: UInt8.self), buffer.count)
        }

        mutating func finalize() -> [UInt8] {
            var output = [UInt8](repeating: 0, count: 32)
            sha3_256_inc_finalize(&output, &state)
            return output
        }
    }
}

/// Overwrites `bytes` in place. `memset_s` is used because it is not elided by
/// the optimizer the way a plain `memset` on dying storage can be.
///
/// Note the limitation inherent to wiping an `Array`: `withUnsafeMutableBytes`
/// requires a uniquely referenced buffer, so if this array shares storage with
/// another, copy-on-write hands us a fresh buffer and the wipe scrubs the copy
/// while the shared original survives. Prefer not to let secret arrays be
/// copied in the first place, and treat this as best effort.
func wipe(_ bytes: inout [UInt8]) {
    guard !bytes.isEmpty else { return }
    bytes.withUnsafeMutableBytes { raw in
        guard let base = raw.baseAddress else { return }
        memset_s(base, raw.count, 0, raw.count)
    }
}

/// Runs `body` with `bytes`, then wipes `bytes` however `body` exits.
func withWiped<T>(_ bytes: inout [UInt8], _ body: ([UInt8]) throws -> T) rethrows -> T {
    defer { wipe(&bytes) }
    return try body(bytes)
}

/// Heap storage for secret key material that clears itself when the last
/// reference goes away.
///
/// Holding the bytes in a class rather than inline in a struct means copying
/// the enclosing value copies a reference, not the secret, so there is exactly
/// one buffer to wipe and copy-on-write can never strand a stale duplicate.
/// The contents are never mutated after `init`, which is what makes the
/// unchecked `Sendable` conformance sound.
final class SecretBytes: @unchecked Sendable {
    private var storage: [UInt8]

    init(_ bytes: [UInt8]) {
        storage = bytes
    }

    var count: Int { storage.count }

    func withBytes<T>(_ body: ([UInt8]) throws -> T) rethrows -> T {
        try body(storage)
    }

    deinit {
        wipe(&storage)
    }
}

/// Moves `bytes` into a `SymmetricKey`, whose storage CryptoKit locks and
/// zeroes on deallocation, and wipes the transient array on the way out.
///
/// One short-lived wiped copy is unavoidable because the PQClean entry points
/// write into a caller-supplied buffer.
func makeSymmetricKey(consuming bytes: inout [UInt8]) -> SymmetricKey {
    defer { wipe(&bytes) }
    return SymmetricKey(data: bytes)
}
