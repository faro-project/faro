// swift-tools-version:5.9
import PackageDescription

// Shared, testable code for the app and its four extensions: where files
// live in the app group, the settings file model, counters and marker
// files (docs/IOS.md §6.3, §6.4, §10.2, §13). It links nothing but
// Foundation, so even the 6 MB extensions can use it, and it never touches
// the Rust core.
let package = Package(
    name: "FaroKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "FaroKit", targets: ["FaroKit"]),
    ],
    targets: [
        .target(name: "FaroKit"),
        .testTarget(name: "FaroKitTests", dependencies: ["FaroKit"]),
    ]
)
