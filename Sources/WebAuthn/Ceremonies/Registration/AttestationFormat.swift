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

public struct AttestationFormat: UnreferencedStringEnumeration, Sendable {
    public var rawValue: String
    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }
    
    public static let packed: Self = "packed"
    public static let tpm: Self = "tpm"
    public static let androidKey: Self = "android-key"
    public static let androidSafetynet: Self = "android-safetynet"
    public static let fidoU2F: Self = "fido-u2f"
    public static let apple: Self = "apple"
    public static let none: Self = "none"
}
