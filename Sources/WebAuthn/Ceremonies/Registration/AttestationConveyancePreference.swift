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
public struct AttestationConveyancePreference: UnreferencedStringEnumeration, Sendable {
    public var rawValue: String
    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }
    
    /// Indicates the Relying Party is not interested in authenticator attestation.
    public static let none: Self = "none"
//    public static let indirect: Self = "indirect"
//    public static let direct: Self = "direct"
//    public static let enterprise: Self = "enterprise"
}
