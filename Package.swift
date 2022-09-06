// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "WalletKit",
    products: [
        .library(
            name: "WalletKit", targets: ["WalletKit"]),
    ],
    targets: [
        .target(
            name: "WalletKit",
            dependencies: [],
            resources: [])
    ]
)
