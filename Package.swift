// swift-tools-version: 6.3
//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2022 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription

let extraSettings: [SwiftSetting] = [
    .treatAllWarnings(as: .error),
    .strictMemorySafety(),
    .enableExperimentalFeature("SuppressedAssociatedTypesWithDefaults"),
    .enableExperimentalFeature("LifetimeDependence"),
    .enableExperimentalFeature("Lifetimes"),
    .enableUpcomingFeature("LifetimeDependence"),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("ExistentialAny"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .enableUpcomingFeature("InternalImportsByDefault"),
]

let package = Package(
    name: "swift-webauthn",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .macCatalyst(.v16),
        .visionOS(.v1),
        .watchOS(.v9),
    ],
    products: [
        .library(name: "WebAuthn", targets: ["WebAuthn"])
    ],
    dependencies: [
        .package(url: "https://github.com/brokenhandsio/swift-cbor.git", from: "0.3.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "3.8.1" ..< "6.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
        .package(url: "https://github.com/swiftlang/swift-docc-plugin.git", from: "1.1.0")
    ],
    targets: [
        .target(
            name: "WebAuthn",
            dependencies: [
                .product(name: "CBOR", package: "swift-cbor"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
            ],
            swiftSettings: extraSettings
        ),
        .testTarget(
            name: "WebAuthnTests",
            dependencies: [
                .target(name: "WebAuthn"),
                .product(name: "CBOR", package: "swift-cbor"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ],
            swiftSettings: extraSettings
        )
    ]
)
