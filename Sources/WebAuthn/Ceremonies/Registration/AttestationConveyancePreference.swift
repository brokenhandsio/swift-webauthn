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

/// Options to specify the Relying Party's preference regarding attestation conveyance during credential generation.
///
/// Currently only supports `none`.
public struct AttestationConveyancePreference: RawRepresentable, Equatable, Hashable, Encodable, Sendable {
    public let rawValue: String
    
    public init?(rawValue: String) {
        switch rawValue {
        case "none":
            self.rawValue = rawValue
        default:
            return nil
        }
    }
    
    private init(_ rawValue: String) {
        self.rawValue = rawValue
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
    
    /// Indicates the Relying Party is not interested in authenticator attestation.
    public static let none = AttestationConveyancePreference("none")
//    public static let indirect = AttestationConveyancePreference("indirect")
//    public static let direct = AttestationConveyancePreference("direct")
//    public static let enterprise = AttestationConveyancePreference("enterprise")
}

extension AttestationConveyancePreference: CustomStringConvertible {
    public var description: String { rawValue }
}
