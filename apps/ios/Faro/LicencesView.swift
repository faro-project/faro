import SwiftUI

/// The licences of the software in the app: the Rust crates
/// (`third-party.txt`) and the domain list (`domains.txt`), both made by
/// `apps/ios/build-notices.sh` and bundled as resources. A stub screen: it
/// shows the text as it is.
struct LicencesView: View {
    private let sections: [(title: String, text: String?)] = [
        ("Software", Self.read("third-party")),
        ("Domain list", Self.read("domains")),
    ]

    var body: some View {
        List {
            ForEach(sections, id: \.title) { section in
                Section(section.title) {
                    if let text = section.text {
                        Text(text)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                    } else {
                        Text("This build doesn't include the licence text.")
                    }
                }
            }
        }
        .navigationTitle("Licences")
        .navigationBarTitleDisplayMode(.inline)
    }

    private static func read(_ name: String) -> String? {
        Bundle.main.url(forResource: name, withExtension: "txt")
            .flatMap { try? String(contentsOf: $0, encoding: .utf8) }
    }
}
