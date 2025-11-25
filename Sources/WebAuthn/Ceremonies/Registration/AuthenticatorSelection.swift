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
/// - SeeAlso: [WebAuthn Level 3 Working Draft §5.4.4. Authenticator Selection Criteria](https://www.w3.org/TR/webauthn-3/#dictionary-authenticatorSelection)
public struct AuthenticatorSelection: Codable, Sendable, Hashable {
    /// If present, indicates the Relying Party's preference for authenticator attachment.
    /// - SeeAlso: [WebAuthn Level 3 Working Draft §5.4.4. Authenticator Selection Criteria](https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-authenticatorattachment)
    public var authenticatorAttachment: AuthenticatorAttachment?
    
    /// Describes the Relying Party's requirements regarding whether the authenticator should create a client-side-resident public key credential source.
    /// - SeeAlso: [WebAuthn Level 3 Working Draft §5.4.4. Authenticator Selection Criteria](https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-residentkey)
    public var residentKey: ResidentKeyRequirement?
    
    /// Describes the Relying Party's requirements regarding user verification.
    /// - SeeAlso: [WebAuthn Level 3 Working Draft §5.4.4. Authenticator Selection Criteria](https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-userverification)
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

extension AuthenticatorSelection {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.authenticatorAttachment = try container.decodeIfPresent(
            AuthenticatorAttachment.self, forKey: .authenticatorAttachment)
        self.residentKey = try container.decodeIfPresent(
            ResidentKeyRequirement.self, forKey: .residentKey)
        self.userVerification = try container.decodeIfPresent(
            UserVerificationRequirement.self, forKey: .userVerification)

        // requireResidentKey is ignored during decoding as it's derived from residentKey
        // It's only included in encoding for backwards compatibility with WebAuthn Level 1
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encodeIfPresent(authenticatorAttachment, forKey: .authenticatorAttachment)
        try container.encodeIfPresent(residentKey, forKey: .residentKey)
        try container.encodeIfPresent(userVerification, forKey: .userVerification)

        // requireResidentKey is included for backwards compatibility with WebAuthn Level 1
        // It should be true if and only if residentKey is set to .required
        let requireResidentKey = residentKey == .required
        try container.encode(requireResidentKey, forKey: .requireResidentKey)
    }

    private enum CodingKeys: String, CodingKey {
        case authenticatorAttachment
        case residentKey
        case userVerification
        case requireResidentKey
    }
}

