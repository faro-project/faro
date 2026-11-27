// swift-tools-version:5.9
import PackageDescription

// Shared, testable code for the app and its four extensions: where files
// live in the app group, the settings file model, counters and marker
// files (docs/IOS.md §6.3, §6.4, §10.2, §13). It links nothing but
// Foundation, so even the 6 MB extensions can use it, and it never touches
// the Rust core. FaroKitApp is the part only the app and the tunnel use
// (Leave Faro, the VPN and context checks), kept out of the extensions.
let package = Package(
    name: "FaroKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "FaroKit", targets: ["FaroKit"]),
        .library(name: "FaroKitApp", targets: ["FaroKitApp"]),
    ],
    targets: [
        .target(name: "FaroKit"),
        .target(name: "FaroKitApp", dependencies: ["FaroKit"]),
        .testTarget(name: "FaroKitTests", dependencies: ["FaroKit", "FaroKitApp"]),
    ]
)
