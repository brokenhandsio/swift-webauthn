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

/// An error that occured preparing or processing WebAuthn-related requests.
@nonexhaustive
public enum WebAuthnError: Error, Hashable, Sendable {
    // MARK: Shared
    case attestedCredentialDataMissing
    case relyingPartyIDHashDoesNotMatch
    case userPresentFlagNotSet
    case invalidSignature

    // MARK: AttestationObject
    case userVerificationRequiredButFlagNotSet
    case attestationStatementMustBeEmpty
    case attestationVerificationNotSupported

    // MARK: WebAuthnManager
    case invalidUserID
    case unsupportedCredentialPublicKeyAlgorithm
    case credentialIDAlreadyExists
    case userVerifiedFlagNotSet
    case potentialReplayAttack
    case invalidAssertionCredentialType

    // MARK: ParsedAuthenticatorAttestationResponse
    case invalidAttestationObject
    case invalidAuthData
    case invalidFmt
    case missingAttStmt
    case attestationFormatNotSupported

    // MARK: ParsedCredentialCreationResponse
    case invalidCredentialCreationType
    case credentialRawIDTooLong

    // MARK: AuthenticatorData
    case authDataTooShort
    case attestedCredentialFlagNotSet
    case extensionDataMissing
    case leftOverBytesInAuthenticatorData
    case credentialIDTooLong
    case credentialIDTooShort
    case invalidPublicKeyLength

    // MARK: CredentialPublicKey
    case badPublicKeyBytes
    case invalidKeyType
    case invalidAlgorithm
    case invalidCurve
    case invalidXCoordinate
    case invalidYCoordinate
    case unsupportedCOSEAlgorithm
    case unsupportedCOSEAlgorithmForEC2PublicKey
    case invalidModulus
    case invalidExponent
    case unsupportedCOSEAlgorithmForRSAPublicKey
    case unsupported
}
