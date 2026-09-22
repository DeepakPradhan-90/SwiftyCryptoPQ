import Foundation
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
}

/// Overwrites `bytes` in place. `memset_s` is used because it is not elided by
/// the optimizer the way a plain `memset` on dying storage can be.
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
