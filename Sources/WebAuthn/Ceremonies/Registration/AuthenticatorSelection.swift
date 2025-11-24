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

/// A dictionary describing the Relying Party's requirements regarding authenticator attributes.
///
/// - SeeAlso: https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria
public struct AuthenticatorSelection: Codable, Sendable {
    /// If present, indicates the Relying Party's preference for authenticator attachment.
    public var authenticatorAttachment: AuthenticatorAttachment?
    
    /// Describes the Relying Party's requirements regarding whether the authenticator should create a client-side-resident public key credential source.
    public var residentKey: ResidentKeyRequirement?
    
    /// Describes the Relying Party's requirements regarding user verification.
    public var userVerification: UserVerificationRequirement?
    
    public init(
        authenticatorAttachment: AuthenticatorAttachment? = nil,
        residentKey: ResidentKeyRequirement? = nil,
        userVerification: UserVerificationRequirement? = nil
    ) {
        self.authenticatorAttachment = authenticatorAttachment
        self.residentKey = residentKey
        self.userVerification = userVerification
    }
}

