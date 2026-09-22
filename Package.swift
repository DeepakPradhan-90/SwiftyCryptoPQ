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
        .executableTarget(
            name: "CryptoPQExample",
            dependencies: ["CryptoPQ"],
            path: "Sources/CryptoPQExample"
        ),
        .testTarget(
            name: "CryptoPQTests",
            dependencies: ["CryptoPQ"],
            path: "Tests/CryptoPQTests",
            resources: [.copy("Vectors")]
        )
    ]
)
