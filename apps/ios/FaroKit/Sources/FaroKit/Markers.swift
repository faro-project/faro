import Foundation
import Darwin

/// Marker files: a file in the app group whose name is the signal and
/// whose content is a Unix time in milliseconds (docs/IOS.md §10.2, such as
/// the tunnel's "alive" timestamp). Written by one process, read by another.
public struct Markers: Sendable {
    public let directory: URL

    public init(directory: URL) {
        self.directory = directory
    }

    public init(group: AppGroup) {
        self.init(directory: group.markersDirectory)
    }

    /// Records `name` as set at `nowMs`.
    public func touch(_ name: String, nowMs: Int64) throws {
        try Markers.check(name)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data(String(nowMs).utf8).write(to: directory.appendingPathComponent(name), options: .atomic)
    }

    /// When `name` was last set, or `nil` if it never was (or the file is unreadable).
    public func read(_ name: String) -> Int64? {
        guard (try? Markers.check(name)) != nil,
              let data = try? Data(contentsOf: directory.appendingPathComponent(name)),
              let text = String(data: data, encoding: .utf8)
        else { return nil }
        return Int64(text)
    }

    /// Whether `name` was set within `maxAgeMs` of `nowMs`.
    public func isFresh(_ name: String, nowMs: Int64, maxAgeMs: Int64) -> Bool {
        guard let at = read(name) else { return false }
        return nowMs - at <= maxAgeMs
    }

    public func remove(_ name: String) {
        guard (try? Markers.check(name)) != nil else { return }
        try? FileManager.default.removeItem(at: directory.appendingPathComponent(name))
    }

    /// Names are plain file names, so a marker can't point outside its directory.
    static func check(_ name: String) throws {
        let ok = !name.isEmpty && name.count <= 64
            && name.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_" || $0 == "-") }
        guard ok else { throw MarkerError.badName(name) }
    }
}

public enum MarkerError: Error, Equatable {
    case badName(String)
}

/// A counter in a small file, safe to add to from several processes at
/// once (the shield extensions and the app): each increment holds an
/// exclusive `flock` across read and write. It records how many times, never
/// what (docs/IOS.md §6.4).
public struct Counter: Sendable {
    public let url: URL

    public init(url: URL) {
        self.url = url
    }

    public init(group: AppGroup, name: String) throws {
        try Markers.check(name)
        self.init(url: group.countersDirectory.appendingPathComponent(name))
    }

    /// Adds `amount` and returns the new value.
    @discardableResult
    public func increment(by amount: UInt64 = 1) throws -> UInt64 {
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let fd = open(url.path, O_RDWR | O_CREAT, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { flock(fd, LOCK_UN) }

        var buffer = [UInt8](repeating: 0, count: 32)
        let n = pread(fd, &buffer, buffer.count, 0)
        let current = n > 0 ? UInt64(String(decoding: buffer[0..<n], as: UTF8.self)) ?? 0 : 0
        let next = current &+ amount
        let text = Array(String(next).utf8)
        guard ftruncate(fd, 0) == 0, pwrite(fd, text, text.count, 0) == text.count else {
            throw CocoaError(.fileWriteUnknown)
        }
        return next
    }

    /// The current value, 0 if there is none.
    public func value() -> UInt64 {
        guard let data = try? Data(contentsOf: url) else { return 0 }
        return UInt64(String(decoding: data, as: UTF8.self)) ?? 0
    }
}
