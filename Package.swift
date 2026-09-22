// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SwiftyCryptoPQ",
    platforms: [
        .iOS(.v15),
        .macOS(.v11)
    ],
    products: [
        .library(
            name: "CryptoPQ",
            targets: ["CryptoPQ"]
        )
    ],
    dependencies: [],
    targets: [
        .target(
            name: "CryptoPQC",
            dependencies: [],
            path: "Sources/CryptoPQC",
            linkerSettings: [
                .linkedFramework("Security")
            ]
        ),
        .target(
            name: "CryptoPQ",
            dependencies: ["CryptoPQC"],
            path: "Sources/CryptoPQ"
        ),
        .testTarget(
            name: "CryptoPQTests",
            dependencies: ["CryptoPQ"],
            path: "Tests/CryptoPQTests",
            resources: [.copy("Vectors")]
        ),

        // Demonstration code, kept out of Sources so that nothing a consumer
        // builds depends on it. The usage tests compile the snippets printed in
        // the README, so the documentation cannot drift.
        .executableTarget(
            name: "CryptoPQExample",
            dependencies: ["CryptoPQ"],
            path: "Examples/CryptoPQExample"
        ),
        .testTarget(
            name: "CryptoPQUsageTests",
            dependencies: ["CryptoPQ"],
            path: "Examples/UsageTests"
        )
    ]
)
