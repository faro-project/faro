// swift-tools-version:5.9
import PackageDescription

// Shared, testable code for the app and its four extensions: where files
// live in the app group, the settings file model, counters and marker
// files (docs/IOS.md §6.3, §6.4, §10.2, §13). It links nothing but
// Foundation, so even the 6 MB extensions can use it, and it never touches
// the Rust core. FaroKit holds only what an extension calls; FaroKitApp is
// the rest, which only the app and the tunnel use (Leave Faro, setup,
// enrollment, the VPN and context checks), kept out of the extensions
// (check-extension-sizes.sh fails if one links it).
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
