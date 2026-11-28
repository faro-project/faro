import SwiftUI

/// The licences of the software in the app: the Rust crates
/// (`third-party.txt`) and the domain list (`domains.txt`), both made by
/// `apps/ios/build-notices.sh` and bundled as resources, and the interface
/// font (`Faro/Fonts/FiraCode-OFL.txt`, checked in). A stub screen: it shows
/// the text as it is.
struct LicencesView: View {
    private let sections: [(title: String, text: String?)] = [
        ("Software", Self.read("third-party")),
        ("Domain list", Self.read("domains")),
        ("Font: Fira Code", Self.read("FiraCode-OFL")),
    ]

    var body: some View {
        List {
            ForEach(sections, id: \.title) { section in
                Section {
                    if let text = section.text {
                        Text(text)
                            .font(.mono(11, relativeTo: .caption))
                            .foregroundStyle(Theme.muted)
                            .textSelection(.enabled)
                    } else {
                        Text("This build doesn't include the licence text.")
                    }
                } header: {
                    Eyebrow(section.title)
                }
                .faroRows()
            }
        }
        .faroList()
        .navigationTitle("Licences")
        .navigationBarTitleDisplayMode(.inline)
    }

    private static func read(_ name: String) -> String? {
        Bundle.main.url(forResource: name, withExtension: "txt")
            .flatMap { try? String(contentsOf: $0, encoding: .utf8) }
    }
}
