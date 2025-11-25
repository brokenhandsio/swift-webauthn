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
import Crypto
@preconcurrency import SwiftCBOR

/// Contains the cryptographic attestation that a new key pair was created by that authenticator.
public struct AttestationObject: Sendable {
    let authenticatorData: AuthenticatorData
    let rawAuthenticatorData: [UInt8]
    let format: AttestationFormat
    let attestationStatement: CBOR

    /// The Authenticator Attestation Globally Unique Identifier (AAGUID) from the attestation object.
    /// Returns nil if attested credential data is not present.
    /// - SeeAlso: [WebAuthn Level 3 Editor's Draft §6.5.1. Attested Credential Data](https://w3c.github.io/webauthn/#sctn-attested-credential-data)
    public var aaguid: AAGUID? {
        authenticatorData.attestedData?.authenticatorAttestationGUID
    }

    func verify(
        relyingPartyID: String,
        verificationRequired: Bool,
        requireUserPresence: Bool = true,
        clientDataHash: SHA256.Digest,
        supportedPublicKeyAlgorithms: [PublicKeyCredentialParameters],
        pemRootCertificatesByFormat: [AttestationFormat: [Data]] = [:]
    ) async throws -> AttestedCredentialData {
        let relyingPartyIDHash = SHA256.hash(data: Data(relyingPartyID.utf8))

        guard relyingPartyIDHash == authenticatorData.relyingPartyIDHash else {
            throw WebAuthnError.relyingPartyIDHashDoesNotMatch
        }

        if requireUserPresence {
            guard authenticatorData.flags.userPresent else {
                throw WebAuthnError.userPresentFlagNotSet
            }
        }

        if verificationRequired {
            guard authenticatorData.flags.userVerified else {
                throw WebAuthnError.userVerificationRequiredButFlagNotSet
            }
        }

        guard let attestedCredentialData = authenticatorData.attestedData else {
            throw WebAuthnError.attestedCredentialDataMissing
        }

        // Step 17.
        let credentialPublicKey = try CredentialPublicKey(publicKeyBytes: attestedCredentialData.publicKey)
        guard supportedPublicKeyAlgorithms.map(\.alg).contains(credentialPublicKey.key.algorithm) else {
            throw WebAuthnError.unsupportedCredentialPublicKeyAlgorithm
        }

        // let pemRootCertificates = pemRootCertificatesByFormat[format] ?? []
        switch format {
        case .none:
            // if format is `none` statement must be empty
            guard attestationStatement == .map([:]) else {
                throw WebAuthnError.attestationStatementMustBeEmpty
            }
        // case .packed:
        //     try await PackedAttestation.verify(
        //         attStmt: attestationStatement,
        //         authenticatorData: rawAuthenticatorData,
        //         clientDataHash: Data(clientDataHash),
        //         credentialPublicKey: credentialPublicKey,
        //         pemRootCertificates: pemRootCertificates
        //     )
        // case .tpm:
        //     try TPMAttestation.verify(
        //         attStmt: attestationStatement,
        //         authenticatorData: rawAuthenticatorData,
        //         attestedCredentialData: attestedCredentialData,
        //         clientDataHash: Data(clientDataHash),
        //         credentialPublicKey: credentialPublicKey,
        //         pemRootCertificates: pemRootCertificates
        //     )
        default:
            throw WebAuthnError.attestationVerificationNotSupported
        }

        return attestedCredentialData
    }
}
