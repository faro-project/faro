import Darwin

/// The resolvers the system would use, read with libresolv
/// (`faro_system_resolvers` in the bridging header). Addresses only, as
/// `DnsFilter.setUpstreams` takes them: `192.168.1.1`, `2001:db8::1`, or
/// `fe80::1%4` with the interface index of a link-local address.
enum SystemResolvers {
    static func read() -> [String] {
        var storage = [sockaddr_storage](repeating: sockaddr_storage(), count: 8)
        let n = Int(faro_system_resolvers(&storage, Int32(storage.count)))
        var out: [String] = []
        for var s in storage.prefix(max(0, min(n, storage.count))) {
            switch Int32(s.ss_family) {
            case AF_INET:
                var sin = withUnsafeBytes(of: &s) { $0.load(as: sockaddr_in.self) }
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                guard inet_ntop(AF_INET, &sin.sin_addr, &buf, socklen_t(buf.count)) != nil else { continue }
                out.append(String(cString: buf))
            case AF_INET6:
                var sin6 = withUnsafeBytes(of: &s) { $0.load(as: sockaddr_in6.self) }
                var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                guard inet_ntop(AF_INET6, &sin6.sin6_addr, &buf, socklen_t(buf.count)) != nil else { continue }
                let ip = String(cString: buf)
                out.append(sin6.sin6_scope_id == 0 ? ip : "\(ip)%\(sin6.sin6_scope_id)")
            default:
                continue
            }
        }
        return out
    }
}
