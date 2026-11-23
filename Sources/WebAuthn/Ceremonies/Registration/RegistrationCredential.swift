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

import Crypto

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The unprocessed response received from `navigator.credentials.create()`.
///
/// When decoding using `Decodable`, `id` and `rawId` must be the same canonical base64url-encoded credential ID.
public struct RegistrationCredential: Sendable {
    /// The credential ID of the newly created credential.
    public let id: CredentialID

    /// Value will always be ``CredentialType/publicKey`` (for now)
    public let type: CredentialType

    /// The attestation response from the authenticator.
    public let attestationResponse: AuthenticatorAttestationResponse

    public init(id: CredentialID, type: CredentialType, attestationResponse: AuthenticatorAttestationResponse) {
        self.id = id
        self.type = type
        self.attestationResponse = attestationResponse
    }
}

extension RegistrationCredential: Codable {
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
        type = try container.decode(CredentialType.self, forKey: .type)
        attestationResponse = try container.decode(AuthenticatorAttestationResponse.self, forKey: .attestationResponse)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        let encodedID = id.base64URLEncoded

        try container.encode(encodedID, forKey: .id)
        try container.encode(type, forKey: .type)
        try container.encode(encodedID, forKey: .rawID)
        try container.encode(attestationResponse, forKey: .attestationResponse)
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case type
        case rawID = "rawId"
        case attestationResponse = "response"
    }
}

/// The processed response received from `navigator.credentials.create()`.
struct ParsedCredentialCreationResponse {
    let id: CredentialID
    /// Value will always be ``CredentialType/publicKey`` (for now)
    let type: CredentialType
    let raw: AuthenticatorAttestationResponse
    let response: ParsedAuthenticatorAttestationResponse

    /// Create a `ParsedCredentialCreationResponse` from a raw `CredentialCreationResponse`.
    init(from rawResponse: RegistrationCredential) throws {
        id = rawResponse.id

        guard rawResponse.type == .publicKey
        else { throw WebAuthnError.invalidCredentialCreationType }
        type = rawResponse.type

        raw = rawResponse.attestationResponse
        response = try ParsedAuthenticatorAttestationResponse(from: raw)
    }

    // swiftlint:disable:next function_parameter_count
    func verify(
        storedChallenge: [UInt8],
        verifyUser: Bool,
        relyingPartyID: String,
        relyingPartyOrigin: String,
        supportedPublicKeyAlgorithms: [PublicKeyCredentialParameters],
        pemRootCertificatesByFormat: [AttestationFormat: [Data]]
    ) async throws -> AttestedCredentialData {
        // Step 7. - 9.
        try response.clientData.verify(
            storedChallenge: storedChallenge,
            ceremonyType: .create,
            relyingPartyOrigin: relyingPartyOrigin
        )

        // Step 10.
        let hash = SHA256.hash(data: Data(raw.clientDataJSON))

        // CBOR decoding happened already. Skipping Step 11.

        // Step 12. - 17.
        let attestedCredentialData = try await response.attestationObject.verify(
            relyingPartyID: relyingPartyID,
            verificationRequired: verifyUser,
            clientDataHash: hash,
            supportedPublicKeyAlgorithms: supportedPublicKeyAlgorithms,
            pemRootCertificatesByFormat: pemRootCertificatesByFormat
        )

        // Step 23.
        guard id.bytes.count <= 1023 else {
            throw WebAuthnError.credentialRawIDTooLong
        }

        // The client-supplied ID isn't covered by the attestation, so it must match the authenticator data.
        guard id == CredentialID(bytes: attestedCredentialData.credentialID) else {
            throw WebAuthnError.credentialIDMismatch
        }

        return attestedCredentialData
    }
}
