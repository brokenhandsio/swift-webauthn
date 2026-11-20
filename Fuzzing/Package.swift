// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "Fuzzing",
    platforms: [
        .macOS(.v26),
        .iOS(.v26),
        .tvOS(.v26),
        .macCatalyst(.v26),
        .visionOS(.v26),
        .watchOS(.v26),
    ],
    dependencies: [
        // The `package:` label for a path dependency is the *directory* name,
        // not the name declared in its Package.swift.
        .package(path: "../"),
        .package(url: "https://github.com/brokenhandsio/swift-fuzz.git", from: "1.0.0"),
    ],
    targets: [
        // A pure-C executable holding libFuzzer's entry points, and a Swift
        // library holding the harness.
        .executableTarget(
            name: "WebAuthnRegistration",
            dependencies: ["WebAuthnRegistrationTarget"],
            path: "FuzzTargets/WebAuthnRegistrationShim"
        ),
        .target(
            name: "WebAuthnRegistrationTarget",
            dependencies: [
                .product(name: "Fuzzing", package: "swift-fuzz"),
                .product(name: "WebAuthn", package: "swift-webauthn"),
            ],
            path: "FuzzTargets/WebAuthnRegistration",
            plugins: [.plugin(name: "FuzzTargetPlugin", package: "swift-fuzz")]
        ),

        .executableTarget(
            name: "WebAuthnAuthentication",
            dependencies: ["WebAuthnAuthenticationTarget"],
            path: "FuzzTargets/WebAuthnAuthenticationShim"
        ),
        .target(
            name: "WebAuthnAuthenticationTarget",
            dependencies: [
                .product(name: "Fuzzing", package: "swift-fuzz"),
                .product(name: "WebAuthn", package: "swift-webauthn"),
            ],
            path: "FuzzTargets/WebAuthnAuthentication",
            plugins: [.plugin(name: "FuzzTargetPlugin", package: "swift-fuzz")]
        ),
    ]
)
