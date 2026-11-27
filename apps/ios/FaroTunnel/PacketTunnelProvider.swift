import Darwin
import FaroKit
import Network
import NetworkExtension
import os

private let log = Logger(subsystem: "org.faro.ios.tunnel", category: "tunnel")

/// The DNS filter's packet tunnel (docs/IOS.md §7, §10.1): a VPN in name
/// only. Only the DNS address and the known encrypted-DNS resolvers are
/// routed into it. Every DNS packet goes to the Rust `DnsFilter`, which
/// decides; this class only moves bytes between the packet flow and the
/// network's own resolvers, and keeps the timers:
///
/// * a heartbeat every 5 minutes while awake, `sleeping` from `sleep`, and
///   a fresh one on `wake`, all through the Rust core, which signs them
///   (skipped while the keys are locked: the filter never waits for them);
/// * the "tunnel alive" marker every minute, which the monitor extension
///   and the app watch;
/// * every 10 minutes: the counters saved to the app group, the member's
///   choices and a newer installed domain list picked up, and the memory
///   left logged.
///
/// Nothing here writes, logs or keeps a looked-up name.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    /// Packets, upstream sockets and the filter.
    private let queue = DispatchQueue(label: "org.faro.ios.tunnel.dns", qos: .userInitiated)
    /// Calls into the Rust core that block (database, network).
    private let coreQueue = DispatchQueue(label: "org.faro.ios.tunnel.core", qos: .utility)

    private let group = AppGroup.container()
    private let network = tunnelNetwork()
    private var filter: DnsFilter?
    private var upstream: Upstream?
    private var timers: [DispatchSourceTimer] = []
    private var pathMonitor: NWPathMonitor?
    private var pathKey: String?
    private var rereading = false
    private var lastReread: Date = .distantPast
    private var awake = true
    /// Only touched on `coreQueue`.
    private var core: FaroCore?

    static let heartbeatInterval: TimeInterval = 5 * 60
    static let markerInterval: TimeInterval = 60
    static let flushInterval: TimeInterval = 10 * 60
    /// How long `sleep` waits for its heartbeat before letting the phone sleep.
    static let sleepHeartbeatWait: TimeInterval = 5

    // MARK: Lifecycle

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        queue.async { [self] in
            let filter: DnsFilter
            do {
                filter = try DnsFilter(
                    packagedManifest: Bundle.main.url(forResource: "domains.manifest", withExtension: "json")?.path,
                    configJson: readText(group?.filterConfigFile),
                    savedCountersJson: readText(group?.dnsCountersFile))
            } catch {
                log.error("the DNS filter did not start: \(String(describing: error), privacy: .public)")
                completionHandler(error)
                return
            }
            self.filter = filter
            logStatus("started")
            upstream = Upstream(
                queue: queue,
                onAnswer: { [weak self] server, answer, tcp in
                    guard let self, let filter = self.filter else { return }
                    self.perform(filter.handleAnswer(
                        server: server, answer: answer, tcp: tcp, nowMs: Self.nowMs(), screenOn: self.awake))
                },
                onFailure: { [weak self] id in
                    guard let self, let filter = self.filter else { return }
                    self.perform(filter.upstreamFailed(id: id, nowMs: Self.nowMs()))
                })
            // The network's resolvers, read before the tunnel's own DNS
            // settings hide them.
            useResolvers(SystemResolvers.read(), reason: "start")
            setTunnelNetworkSettings(settings(withDNS: true)) { error in
                self.queue.async {
                    if let error {
                        log.error("network settings refused: \(String(describing: error), privacy: .public)")
                        completionHandler(error)
                        return
                    }
                    self.readPackets()
                    self.startPathMonitor()
                    self.startTimers()
                    self.touchMarker()
                    completionHandler(nil)
                    self.coreQueue.async {
                        self.refreshFromCore()
                        self.heartbeat(.active)
                    }
                }
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        queue.async { [self] in
            log.notice("stopping (reason \(reason.rawValue, privacy: .public))")
            flushCounters()
            for t in timers {
                t.cancel()
            }
            timers = []
            pathMonitor?.cancel()
            pathMonitor = nil
            upstream?.stop()
            // No `shutting_down` heartbeat: the tunnel stopping while the
            // phone runs is what the monitor reports as the filter being off,
            // and the instance should not read it as an expected silence.
            completionHandler()
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        queue.async { [self] in
            awake = false
            flushCounters()
            let once = Once()
            let finish = { once.run(completionHandler) }
            queue.asyncAfter(deadline: .now() + Self.sleepHeartbeatWait, execute: finish)
            coreQueue.async {
                self.heartbeat(.sleeping)
                finish()
            }
        }
    }

    override func wake() {
        queue.async { [self] in
            awake = true
            touchMarker()
            coreQueue.async { self.heartbeat(.active) }
        }
    }

    // MARK: Network settings

    /// The settings of docs/IOS.md §7.1: a private address on each family,
    /// host routes for the DNS address and the resolver list only, and,
    /// with `withDNS`, the DNS address for every name (`matchDomains = [""]`).
    private func settings(withDNS: Bool) -> NEPacketTunnelNetworkSettings {
        let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: network.ipv4Address)
        s.mtu = NSNumber(value: network.mtu)
        let v4 = NEIPv4Settings(addresses: [network.ipv4Address], subnetMasks: ["255.255.255.255"])
        v4.includedRoutes = network.ipv4Routes.map {
            NEIPv4Route(destinationAddress: $0, subnetMask: "255.255.255.255")
        }
        v4.excludedRoutes = []
        s.ipv4Settings = v4
        let v6 = NEIPv6Settings(addresses: [network.ipv6Address], networkPrefixLengths: [128])
        v6.includedRoutes = network.ipv6Routes.map {
            NEIPv6Route(destinationAddress: $0, networkPrefixLength: 128)
        }
        v6.excludedRoutes = []
        s.ipv6Settings = v6
        if withDNS {
            let dns = NEDNSSettings(servers: [network.ipv4Dns, network.ipv6Dns])
            dns.matchDomains = [""]
            s.dnsSettings = dns
        }
        return s
    }

    // MARK: Packets

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            self.queue.async {
                guard let filter = self.filter else { return }
                let now = Self.nowMs()
                for p in packets {
                    self.perform(filter.handlePacket(packet: p, nowMs: now, screenOn: self.awake))
                }
                self.readPackets()
            }
        }
    }

    private func perform(_ step: DnsStep) {
        switch step {
        case .reply(let packets):
            let protocols = packets.map { p -> NSNumber in
                NSNumber(value: (p.first ?? 0) >> 4 == 6 ? AF_INET6 : AF_INET)
            }
            packetFlow.writePackets(packets, withProtocols: protocols)
        case .send(let server, let payload):
            upstream?.send(payload, to: server)
        case .sendTcp(let server, let id, let payload):
            upstream?.fetchOverTcp(payload, from: server, id: id)
        case .nothing:
            break
        }
    }

    // MARK: Upstream resolvers

    /// Use `servers` (as the system reported them) if any is usable. The
    /// tunnel's own addresses never are: once its DNS settings apply, the
    /// system reports them in place of the network's.
    @discardableResult
    private func useResolvers(_ servers: [String], reason: String) -> Bool {
        guard let filter else { return false }
        let kept = filter.setUpstreams(servers: servers)
        upstream?.use(kept)
        if kept.isEmpty {
            // Fail closed: allowed names get SERVFAIL until a resolver is
            // found. Never a public resolver in its place.
            log.error("no usable resolver (\(reason, privacy: .public)): lookups fail until one is found")
        } else {
            log.notice("using \(kept.count, privacy: .public) resolver(s) (\(reason, privacy: .public))")
        }
        return !kept.isEmpty
    }

    private func isOwn(_ s: String) -> Bool {
        [network.ipv4Dns, network.ipv6Dns, network.ipv4Address, network.ipv6Address].contains(s)
    }

    /// Read the network's resolvers again. While the tunnel's DNS settings
    /// apply, the system reports the tunnel's own address, so they are
    /// lifted for a moment (routes stay), read, and put back. During that
    /// moment, well under a second, lookups go to the network's resolvers
    /// without the filter: a known gap, docs/IOS.md §7.4.
    private func rereadResolvers(reason: String) {
        let direct = SystemResolvers.read().filter { !isOwn($0) }
        if !direct.isEmpty {
            useResolvers(direct, reason: reason)
            return
        }
        guard !rereading else { return }
        rereading = true
        lastReread = Date()
        setTunnelNetworkSettings(settings(withDNS: false)) { _ in
            self.queue.async { self.readWhileLifted(attempt: 0, reason: reason) }
        }
    }

    private func readWhileLifted(attempt: Int, reason: String) {
        let found = SystemResolvers.read().filter { !isOwn($0) }
        if found.isEmpty && attempt < 3 {
            queue.asyncAfter(deadline: .now() + 0.15) {
                self.readWhileLifted(attempt: attempt + 1, reason: reason)
            }
            return
        }
        useResolvers(found, reason: reason)
        setTunnelNetworkSettings(settings(withDNS: true)) { error in
            self.queue.async {
                self.rereading = false
                if let error {
                    log.error("DNS settings not restored: \(String(describing: error), privacy: .public)")
                }
            }
        }
    }

    private func startPathMonitor() {
        let m = NWPathMonitor()
        m.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            // What identifies the network: its interfaces and gateways.
            // Tunnels (this one too) are `other` and left out, so applying
            // the tunnel's own settings doesn't count as a change.
            let interfaces = path.availableInterfaces
                .filter { $0.type != .other }
                .map { "\($0.type):\($0.name)" }
            let key = "\(path.status) \(interfaces.joined(separator: ",")) \(path.gateways.map { "\($0)" }.joined(separator: ","))"
            guard key != self.pathKey else { return }
            let first = self.pathKey == nil
            self.pathKey = key
            guard !first, path.status == .satisfied else { return }
            // Let the system finish configuring the new network first.
            self.queue.asyncAfter(deadline: .now() + 1) {
                guard self.pathKey == key else { return }
                self.rereadResolvers(reason: "network change")
            }
        }
        m.start(queue: queue)
        pathMonitor = m
    }

    // MARK: Timers

    private func startTimers() {
        timers = [
            timer(every: Self.markerInterval) { [weak self] in
                guard let self else { return }
                self.touchMarker()
                // No resolver yet: try again, at most every 5 minutes.
                if self.filter?.status().upstreams == 0, Date().timeIntervalSince(self.lastReread) > 300 {
                    self.rereadResolvers(reason: "retry")
                }
            },
            timer(every: Self.heartbeatInterval) { [weak self] in
                guard let self, self.awake else { return }
                self.coreQueue.async { self.heartbeat(.active) }
            },
            timer(every: Self.flushInterval) { [weak self] in
                guard let self else { return }
                self.flushCounters()
                self.logStatus("periodic")
                self.coreQueue.async { self.refreshFromCore() }
            },
        ]
    }

    private func timer(every interval: TimeInterval, _ fire: @escaping () -> Void) -> DispatchSourceTimer {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + interval, repeating: interval, leeway: .seconds(5))
        t.setEventHandler(handler: fire)
        t.resume()
        return t
    }

    // MARK: The app group

    private func touchMarker() {
        guard let group else { return }
        // Fails before the first unlock (the container is protected); the
        // next minute tries again.
        try? Markers(group: group).touch(MarkerName.tunnelAlive, nowMs: Self.nowMs())
    }

    /// Save the counters (blocked lookups only) for the next run and for
    /// the reports. Kept in memory if the container can't be written yet.
    private func flushCounters() {
        guard let group, let filter else { return }
        do {
            try FileManager.default.createDirectory(
                at: group.dnsCountersFile.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(filter.countersJson().utf8).write(to: group.dnsCountersFile, options: .atomic)
        } catch {
            log.info("counters not saved yet: \(String(describing: error), privacy: .public)")
        }
    }

    private func readText(_ url: URL?) -> String? {
        guard let url, let data = try? Data(contentsOf: url) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    // MARK: The Rust core (on coreQueue)

    /// Open the core if it isn't yet (it can't be before the first unlock),
    /// then pick up the instance host, the member's choices and a newer
    /// installed domain list.
    private func refreshFromCore() {
        if core == nil, let group {
            core = try? CoreLink.open(group: group)
        }
        let config = readText(group?.filterConfigFile)
        // Unread (no core yet, or the database can't be opened yet): keep
        // what the filter has.
        let status = try? core?.status()
        queue.async { [self] in
            guard let filter else { return }
            if let status {
                filter.setInstanceHost(host: status.instanceUrl.flatMap { URL(string: $0)?.host?.lowercased() })
            }
            if let config {
                do {
                    try filter.setConfig(configJson: config)
                } catch {
                    log.error("the member's filter choices were refused: \(String(describing: error), privacy: .public)")
                }
            }
        }
        guard let core, let filter = queue.sync(execute: { self.filter }) else { return }
        do {
            if let version = try filter.refreshDomains(core: core) {
                log.notice("switched to the installed domain list \(version, privacy: .public)")
            }
        } catch {
            log.error("installed domain list not loaded: \(String(describing: error), privacy: .public)")
        }
    }

    /// One heartbeat. Before the first unlock the keys are locked, and the
    /// heartbeat waits for the next round; the filter runs regardless.
    private func heartbeat(_ state: HeartbeatState) {
        if core == nil {
            refreshFromCore()
        }
        guard let core else { return }
        do {
            _ = try core.heartbeat(state: state)
        } catch FaroError.KeysLocked {
            log.info("keys locked: heartbeat skipped, filtering continues")
        } catch FaroError.NotEnrolled {
            // Nothing to report to yet.
        } catch {
            log.error("heartbeat failed: \(String(describing: error), privacy: .public)")
        }
    }

    // MARK: Logging

    private func logStatus(_ when: String) {
        guard let s = filter?.status() else { return }
        log.notice("""
            \(when, privacy: .public): domains \(s.domainsVersion ?? "none", privacy: .public) \
            (\(s.domainsSource, privacy: .public)), blocking \(s.blockedCategories.joined(separator: ","), privacy: .public), \
            \(s.upstreams, privacy: .public) resolver(s), \(s.pending, privacy: .public) in flight, \
            \(s.counterBuckets, privacy: .public) bucket(s), \
            memory available \(os_proc_available_memory(), privacy: .public) bytes
            """)
        if let e = s.domainsError {
            log.error("domain list: \(e, privacy: .public)")
        }
        if let e = s.configError {
            log.error("filter choices: \(e, privacy: .public)")
        }
    }

    static func nowMs() -> Int64 {
        Int64((Date().timeIntervalSince1970 * 1000).rounded())
    }
}

/// Runs a closure once, however many times it is asked to.
private final class Once {
    private var done = false
    private let lock = NSLock()

    func run(_ f: () -> Void) {
        lock.lock()
        let first = !done
        done = true
        lock.unlock()
        if first { f() }
    }
}
