import Darwin
import Foundation
import Network

/// The sockets to the network's own resolvers (docs/IOS.md §7.1). The
/// provider's own connections never go through its tunnel, and these also
/// refuse the `other` interface type (tunnels and loopback), so a query
/// can't loop back into the filter.
///
/// One connected UDP connection per resolver carries every forwarded
/// query; answers are matched by the filter, not here. A truncated answer
/// is fetched again on a short-lived TCP connection. Everything runs on
/// the tunnel's queue. Nothing here reads, keeps or logs a payload.
final class Upstream {
    /// An answer: the resolver's key, the DNS message, whether over TCP.
    typealias Answer = (String, Data, Bool) -> Void

    private let queue: DispatchQueue
    private let onAnswer: Answer
    /// A send or TCP fetch for the query with this id failed.
    private let onFailure: (UInt16) -> Void
    private var servers: [String: UpstreamServer] = [:]
    private var connections: [String: NWConnection] = [:]

    /// How long a TCP fetch may take, in seconds. The filter gives up on it
    /// a little later (`TCP_TIMEOUT_MS`).
    static let tcpTimeout: TimeInterval = 8

    init(queue: DispatchQueue, onAnswer: @escaping Answer, onFailure: @escaping (UInt16) -> Void) {
        self.queue = queue
        self.onAnswer = onAnswer
        self.onFailure = onFailure
    }

    /// Use these resolvers from now on, as `DnsFilter.setUpstreams` kept
    /// them. Connections to others are closed.
    func use(_ list: [UpstreamServer]) {
        let keys = Set(list.map(\.key))
        for (key, c) in connections where !keys.contains(key) {
            c.cancel()
            connections[key] = nil
        }
        servers = Dictionary(list.map { ($0.key, $0) }, uniquingKeysWith: { a, _ in a })
    }

    func stop() {
        for c in connections.values {
            c.cancel()
        }
        connections = [:]
        servers = [:]
    }

    /// Send a query over UDP.
    func send(_ payload: Data, to key: String) {
        guard let c = connection(for: key) else { return }
        c.send(content: payload, completion: .contentProcessed { _ in })
    }

    /// Fetch the whole answer over TCP: the length in two bytes, then the
    /// query; the answer comes back the same way.
    func fetchOverTcp(_ payload: Data, from key: String, id: UInt16) {
        guard let server = servers[key], let endpoint = Upstream.endpoint(server), payload.count <= 0xffff else {
            onFailure(id)
            return
        }
        let c = NWConnection(to: endpoint, using: Upstream.parameters(.tcp))
        var done = false
        let finish: (Data?) -> Void = { [weak self] answer in
            guard let self, !done else { return }
            done = true
            c.cancel()
            if let answer {
                self.onAnswer(key, answer, true)
            } else {
                self.onFailure(id)
            }
        }
        queue.asyncAfter(deadline: .now() + Upstream.tcpTimeout) { finish(nil) }
        c.stateUpdateHandler = { state in
            if case .failed = state { finish(nil) }
        }
        var framed = Data([UInt8(payload.count >> 8), UInt8(payload.count & 0xff)])
        framed.append(payload)
        c.send(content: framed, completion: .contentProcessed { error in
            if error != nil { finish(nil) }
        })
        c.receive(minimumIncompleteLength: 2, maximumLength: 2) { head, _, _, _ in
            guard let head, head.count == 2 else { finish(nil); return }
            let bytes = [UInt8](head)
            let length = Int(bytes[0]) << 8 | Int(bytes[1])
            guard length >= 12 else { finish(nil); return }
            c.receive(minimumIncompleteLength: length, maximumLength: length) { body, _, _, _ in
                guard let body, body.count == length else { finish(nil); return }
                finish(body)
            }
        }
        c.start(queue: queue)
    }

    private func connection(for key: String) -> NWConnection? {
        if let c = connections[key] {
            return c
        }
        guard let server = servers[key], let endpoint = Upstream.endpoint(server) else { return nil }
        let c = NWConnection(to: endpoint, using: Upstream.parameters(.udp))
        c.stateUpdateHandler = { [weak self, weak c] state in
            switch state {
            case .failed, .cancelled:
                // Opened again on the next query.
                guard let self, let c, self.connections[key] === c else { return }
                self.connections[key] = nil
            default:
                break
            }
        }
        connections[key] = c
        receive(on: c, key: key)
        c.start(queue: queue)
        return c
    }

    private func receive(on c: NWConnection, key: String) {
        c.receiveMessage { [weak self, weak c] data, _, _, error in
            guard let self, let c else { return }
            if let data, !data.isEmpty {
                self.onAnswer(key, data, false)
            }
            if error == nil {
                self.receive(on: c, key: key)
            }
        }
    }

    private static func parameters(_ base: NWParameters) -> NWParameters {
        let p = base.copy()
        p.prohibitedInterfaceTypes = [.other]
        return p
    }

    /// The resolver's address. A link-local IPv6 address carries its
    /// interface by name, which is how Network.framework takes it.
    static func endpoint(_ s: UpstreamServer) -> NWEndpoint? {
        guard let port = NWEndpoint.Port(rawValue: s.port) else { return nil }
        if let v4 = IPv4Address(s.host) {
            return .hostPort(host: .ipv4(v4), port: port)
        }
        var text = s.host
        if s.scopeId != 0 {
            var name = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
            guard if_indextoname(s.scopeId, &name) != nil else { return nil }
            text += "%" + String(cString: name)
        }
        guard let v6 = IPv6Address(text) else { return nil }
        return .hostPort(host: .ipv6(v6), port: port)
    }
}
