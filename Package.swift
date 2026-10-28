// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "MacSentinel",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "MacSentinel", targets: ["MacSentinel"])],
    dependencies: [
        .package(url: "https://github.com/CocoaLumberjack/CocoaLumberjack", from: "3.9.0")
    ],
    targets: [.executableTarget(name: "MacSentinel", dependencies: [
        .product(name: "CocoaLumberjackSwift", package: "CocoaLumberjack")
    ])]
)
