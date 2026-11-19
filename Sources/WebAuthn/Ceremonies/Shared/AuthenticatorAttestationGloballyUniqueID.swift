//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2024 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(FoundationEssentials)
public import FoundationEssentials
#else
public import Foundation
#endif

/// A globally unique ID identifying an authenticator.
///
/// Each authenticator has an Authenticator Attestation Globally Unique Identifier or **AAGUID**, which is a 128-bit identifier indicating the type (e.g. make and model) of the authenticator. The AAGUID MUST be chosen by its maker to be identical across all substantially identical authenticators made by that maker, and different (with high probability) from the AAGUIDs of all other types of authenticators. The AAGUID for a given type of authenticator SHOULD be randomly generated to ensure this.
///
/// The Relying Party MAY use the AAGUID to infer certain properties of the authenticator, such as certification level and strength of key protection, using information from other sources. The Relying Party MAY use the AAGUID to attempt to identify the maker of the authenticator without requesting and verifying attestation, but the AAGUID is not provably authentic without attestation.
/// - SeeAlso: [WebAuthn Leven 3 Editor's Draft §6. WebAuthn Authenticator Model](https://w3c.github.io/webauthn/#aaguid)
public struct AuthenticatorAttestationGloballyUniqueID: Hashable, Sendable {
    /// The underlying UUID for the authenticator.
    public let id: UUID

    /// Initialize an AAGUID with a UUID.
    @inlinable
    public init(uuid: UUID) {
        self.id = uuid
    }

    /// Initialize an AAGUID with a byte sequence.
    ///
    /// This sequence must be of length ``AuthenticatorAttestationGloballyUniqueID/size``.
    @inlinable
    public init?(bytes: some BidirectionalCollection<UInt8>) {
        guard bytes.count == Self.size else { return nil }
        let b = Array(bytes)
        self.init(
            uuid: UUID(
                uuid: (
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                    b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
                )))
    }

    /// Initialize an AAGUID with a string-based UUID.
    @inlinable
    public init?(uuidString: String) {
        guard let uuid = UUID(uuidString: uuidString)
        else { return nil }

        self.init(uuid: uuid)
    }

    /// Access the AAGUID as an encoded byte sequence.
    @inlinable
    public var bytes: [UInt8] {
        let u = id.uuid
        return [
            u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7,
            u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15,
        ]
    }

    /// The identifier of an anonymized authenticator, set to a byte sequence of 16 zeros.
    public static let anonymous = AuthenticatorAttestationGloballyUniqueID(bytes: Array(repeating: 0, count: Self.size))!

    /// The byte length of an encoded identifer.
    public static let size: Int = 16
}

/// A shorthand for an ``AuthenticatorAttestationGloballyUniqueID``
public typealias AAGUID = AuthenticatorAttestationGloballyUniqueID

extension AuthenticatorAttestationGloballyUniqueID: Codable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        id = try container.decode(UUID.self)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(id)
    }
}
