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

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The unprocessed response received from `navigator.credentials.get()`.
///
/// When decoding using `Decodable`, the `rawID` is decoded from base64url to bytes.
public struct AuthenticationCredential: Sendable {
    /// The credential ID of the newly created credential.
    public let id: CredentialID

    /// The attestation response from the authenticator.
    public let response: AuthenticatorAssertionResponse

    /// Reports the authenticator attachment modality in effect at the time the navigator.credentials.create() or
    /// navigator.credentials.get() methods successfully complete
    public let authenticatorAttachment: AuthenticatorAttachment?

    /// Value will always be ``CredentialType/publicKey`` (for now)
    public let type: CredentialType

    public init(
        id: CredentialID, response: AuthenticatorAssertionResponse, authenticatorAttachment: AuthenticatorAttachment?,
        type: CredentialType
    ) {
        self.id = id
        self.response = response
        self.authenticatorAttachment = authenticatorAttachment
        self.type = type
    }
}

extension AuthenticationCredential: Codable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        let id = try container.decodeCredentialID(forKey: .id)
        let rawID = try container.decodeCredentialID(forKey: .rawID)
        guard id == rawID else {
            throw DecodingError.dataCorruptedError(
                forKey: .rawID,
                in: container,
                debugDescription: "rawId does not match id"
            )
        }

        self.id = id
        response = try container.decode(AuthenticatorAssertionResponse.self, forKey: .response)
        authenticatorAttachment = try container.decodeIfPresent(AuthenticatorAttachment.self, forKey: .authenticatorAttachment)
        type = try container.decode(CredentialType.self, forKey: .type)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        let encodedID = id.base64URLEncoded

        try container.encode(encodedID, forKey: .id)
        try container.encode(encodedID, forKey: .rawID)
        try container.encode(response, forKey: .response)
        try container.encodeIfPresent(authenticatorAttachment, forKey: .authenticatorAttachment)
        try container.encode(type, forKey: .type)
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case rawID = "rawId"
        case response
        case authenticatorAttachment
        case type
    }
}
