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

public struct AttestationFormat: RawRepresentable, Equatable, Hashable, Codable, Sendable {
    public let rawValue: String
    
    public init?(rawValue: String) {
        switch rawValue {
            case "packed", "tpm", "android-key", "android-safetynet", "fido-u2f", "apple", "none":
            self.rawValue = rawValue
        default:
            return nil
        }
    }
    
    private init(_ rawValue: String) {
        self.rawValue = rawValue
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        rawValue = try container.decode(String.self)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
    
    public static let packed = AttestationFormat("packed")
    public static let tpm = AttestationFormat("tpm")
    public static let androidKey = AttestationFormat("android-key")
    public static let androidSafetynet = AttestationFormat("android-safetynet")
    public static let fidoU2F = AttestationFormat("fido-u2f")
    public static let apple = AttestationFormat("apple")
    public static let none = AttestationFormat("none")
}

extension AttestationFormat: CustomStringConvertible {
    public var description: String { rawValue }
}
