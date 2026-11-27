import FaroKit
import Foundation

/// An enrollment link, `faro://enroll?i=<instance URL>&c=<code>[&m=<member key id>]`
/// (docs/IOS.md §14, ARCHITECTURE.md §3.8). This parses only enough for the
/// app to decide what it was handed: a link from the camera, from the `faro`
/// URL scheme or from the pasteboard. The Rust core parses it again,
/// strictly, before anything is sent anywhere.
public struct EnrollLink: Equatable, Sendable {
    /// The link as the core takes it, trimmed.
    public let text: String
    /// The instance's address, `https` (or `http` for a local test instance).
    public let instance: URL
    /// The code, upper-cased with a hyphen after four characters.
    public let code: String
    /// The member key fingerprint the link names, if it does.
    public let memberKey: String?

    /// `nil` unless `input` is, after trimming, a `faro://enroll` link with an
    /// instance URL and an 8-character code.
    public init?(_ input: String) {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count <= 4096,
              let parts = URLComponents(string: trimmed),
              parts.scheme?.lowercased() == "faro",
              parts.host?.lowercased() == "enroll",
              parts.fragment == nil
        else { return nil }
        let items = parts.queryItems ?? []
        // A parameter given twice is refused, as the core does.
        for name in ["i", "c", "m"] where items.filter({ $0.name == name }).count > 1 {
            return nil
        }
        func value(_ name: String) -> String? { items.first { $0.name == name }?.value }

        guard let i = value("i"), let c = value("c"),
              let url = URL(string: i), let scheme = url.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              let host = url.host, !host.isEmpty
        else { return nil }

        let compact = c.uppercased().filter { $0 != "-" && $0 != " " }
        guard compact.count == 8, compact.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) })
        else { return nil }

        self.text = trimmed
        self.instance = url
        self.code = String(compact.prefix(4)) + "-" + String(compact.suffix(4))
        self.memberKey = value("m")
    }

    /// A short name for the instance, such as `faro.example.org`.
    public var instanceHost: String { instance.host ?? instance.absoluteString }
}

/// Finds an enrollment link inside text the member pasted or a QR code held.
public enum EnrollLinkFinder {
    public static func find(in text: String) -> EnrollLink? {
        if let whole = EnrollLink(text) { return whole }
        for word in text.split(whereSeparator: { $0.isWhitespace }) {
            if let link = EnrollLink(String(word)) { return link }
        }
        return nil
    }
}
