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

import Foundation

/// The Relying Party's requirements regarding whether the authenticator should create a client-side-resident public key credential source.
///
/// - SeeAlso: https://www.w3.org/TR/webauthn-2/#enumdef-residentkeyrequirement
public struct ResidentKeyRequirement: UnreferencedStringEnumeration, Sendable {
    public var rawValue: String
    
    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }
    
    /// This value indicates the Relying Party requires a client-side-resident credential (i.e., a discoverable credential).
    /// If the authenticator cannot create a client-side-resident credential, it will return an error.
    public static let required: Self = "required"
    
    /// This value indicates the Relying Party strongly prefers a client-side-resident credential, but will accept a server-side credential.
    public static let preferred: Self = "preferred"
    
    /// This value indicates the Relying Party strongly prefers a server-side credential, but will accept a client-side-resident credential.
    public static let discouraged: Self = "discouraged"
}

