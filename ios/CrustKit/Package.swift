// swift-tools-version: 5.9

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
        .testTarget(
            name: "CrustKitTests",
            dependencies: ["CrustKit"],
            path: "Tests"
        ),
    ]
)
