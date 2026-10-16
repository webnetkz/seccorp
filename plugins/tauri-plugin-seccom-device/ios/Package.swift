// swift-tools-version:5.5

import PackageDescription

let package = Package(
    name: "tauri-plugin-seccom-device",
    platforms: [
        .macOS(.v10_13),
        .iOS(.v14),
    ],
    products: [
        .library(
            name: "tauri-plugin-seccom-device",
            type: .static,
            targets: ["tauri-plugin-seccom-device"]),
    ],
    dependencies: [
        .package(name: "Tauri", path: "../.tauri/tauri-api")
    ],
    targets: [
        .target(
            name: "tauri-plugin-seccom-device",
            dependencies: [
                .byName(name: "Tauri")
            ],
            path: "Sources")
    ]
)
