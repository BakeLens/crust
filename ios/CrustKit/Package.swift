// swift-tools-version: 5.9
// This Package.swift is for reference only — CrustKit is designed to be
// added to an Xcode project alongside the Libcrust.xcframework produced
// by scripts/build-ios.sh.

import PackageDescription

let package = Package(
    name: "CrustKit",
    platforms: [
        .iOS(.v15),
    ],
    products: [
        .library(
            name: "CrustKit",
            targets: ["CrustKit"]
        ),
    ],
    targets: [
        // The Libcrust binary target is produced by gomobile bind.
        // After running scripts/build-ios.sh, copy the xcframework here
        // or reference it via path.
        .binaryTarget(
            name: "Libcrust",
            path: "../../build/ios/Libcrust.xcframework"
        ),
        .target(
            name: "CrustKit",
            dependencies: ["Libcrust"],
            path: "Sources"
        ),
    ]
)
