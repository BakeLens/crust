// swift-tools-version: 5.9

import PackageDescription

// When consuming CrustKit via SPM from a GitHub release, set the
// CRUSTKIT_REMOTE_URL and CRUSTKIT_REMOTE_CHECKSUM environment variables,
// or replace the binaryTarget below with:
//
//   .binaryTarget(
//       name: "Libcrust",
//       url: "https://github.com/BakeLens/crust/releases/download/v<VERSION>/Libcrust.xcframework.zip",
//       checksum: "<SHA256>"
//   )
//
// For local development (after running scripts/build-ios.sh), the path
// target below is used.

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
        // After running scripts/build-ios.sh, the xcframework is at this path.
        // For remote consumption, replace with .binaryTarget(url:checksum:).
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
