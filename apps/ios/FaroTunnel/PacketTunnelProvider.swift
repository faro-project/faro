import FaroKit
import NetworkExtension

/// The DNS filter's packet tunnel (docs/IOS.md §7). A stub: it refuses to
/// start, so it never claims to filter anything it doesn't. The filter
/// comes with its own issue.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        completionHandler(NSError(
            domain: "org.faro.ios.tunnel", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "The Faro tunnel is not implemented yet."]))
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    /// Where the tunnel will open the Rust core. Not called yet; it keeps
    /// the core linked, so the target is built the way it will ship.
    func openCore() throws -> FaroCore {
        guard let group = AppGroup.container() else {
            throw NSError(domain: "org.faro.ios.tunnel", code: 2)
        }
        return try CoreLink.open(group: group)
    }
}
