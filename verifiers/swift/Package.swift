// swift-tools-version:5.9
// The executable Swift counterpart of the offline verifier documented in
// docs/features/CLIENT_SDK.md, pinned to docs/testing/CROSS_VERIFIER_FIXTURES.md.
// Licensed under the Apache License, Version 2.0 (client-side code — embeddable anywhere).
import PackageDescription

let package = Package(
    name: "GrantmintVerifier",
    platforms: [.macOS(.v11), .iOS(.v14)],
    products: [
        .library(name: "GrantmintVerifier", targets: ["GrantmintVerifier"])
    ],
    targets: [
        .target(name: "GrantmintVerifier"),
        .testTarget(name: "GrantmintVerifierTests", dependencies: ["GrantmintVerifier"]),
    ]
)
