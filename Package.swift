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
    targets: [
        .binaryTarget(
            name: "CryptoPQ",
            url: "https://github.com/DeepakPradhan-90/SwiftyCryptoPQ/releases/download/1.0.0/CryptoPQ.xcframework.zip",
            checksum: "29511f91397f062b798113bcbad10a1ce278cb417d7909c5bcbd0fab05292dce"
        )
    ]
)
