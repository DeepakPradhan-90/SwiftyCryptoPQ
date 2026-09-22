import Foundation

/// Opt-in process-level measures that reduce the chance of secret material
/// escaping the process after the fact.
///
/// These are defense in depth against *post-hoc* memory disclosure — core
/// dumps, crash reports, swap files, reused pages. None of them protect against
/// an attacker with live access to a running process or a debugger attached to
/// a jailbroken device. If that is in your threat model, use hardware-backed
/// keys instead.
public enum ProcessHardening {

    /// Sets the core dump size limit to zero, so a crash cannot write process
    /// memory — including keys and shared secrets — to disk.
    ///
    /// Call once during startup, before any key material exists. Returns
    /// `false` if the limit could not be lowered, which can happen if the
    /// platform or sandbox refuses the change.
    ///
    /// On iOS core dumps are not produced for sandboxed apps, so this matters
    /// most on macOS and for command line tools.
    @discardableResult
    public static func disableCoreDumps() -> Bool {
        var limit = rlimit(rlim_cur: 0, rlim_max: 0)
        return setrlimit(RLIMIT_CORE, &limit) == 0
    }

    /// Pins `count` bytes at `pointer` into physical memory so they cannot be
    /// written to swap.
    ///
    /// Each locked region must be released with `unlockMemory` before the
    /// allocation is freed. Locking is a limited resource, so use it for
    /// long-lived key storage rather than per-operation buffers. Relevant on
    /// macOS, which swaps; iOS does not swap app memory, though it does
    /// compress it, which this does not prevent.
    @discardableResult
    public static func lockMemory(_ pointer: UnsafeRawPointer, count: Int) -> Bool {
        mlock(pointer, count) == 0
    }

    /// Releases a region previously pinned with `lockMemory`.
    @discardableResult
    public static func unlockMemory(_ pointer: UnsafeRawPointer, count: Int) -> Bool {
        munlock(pointer, count) == 0
    }
}
