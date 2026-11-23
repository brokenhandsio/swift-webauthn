//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2026 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Testing

@testable import WebAuthn

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

struct CredentialIDTests {
    static let invalidEncodedIDs = ["AR", "AQ==", "+//+AQ==", "not base64 at all!!", "A", " AQ", "AQ\n"]

    static let invalidIDPairs: [(String, String)] = [
        ("AQ", "Ag"),  // Different IDs
        ("AR", "AQ"),  // Non-canonical id
        ("AQ", "AR"),  // Non-canonical rawId
        ("AQ==", "AQ"),  // Padded id
        ("AQ", "AQ=="),  // Padded rawId
        ("+//+AQ==", "-__-AQ"),  // Standard base64 id
        ("-__-AQ", "+//+AQ=="),  // Standard base64 rawId
        ("not base64", "not base64"),
    ]

    static let missingIDPairs: [(String?, String?)] = [("AQ", nil), (nil, "AQ")]

    static let registrationResponse = #"{"clientDataJSON":"AQ","attestationObject":"AQ"}"#
    static let authenticationResponse = #"{"clientDataJSON":"AQ","authenticatorData":"AQ","signature":"AQ"}"#

    private struct EncodedIDs: Decodable {
        let id: String
        let rawId: String
    }

    private static func json(id: String?, rawID: String?, response: String) -> Data {
        var fields = [#""type":"public-key""#, #""response":\#(response)"#]
        if let id {
            fields.append(#""id":"\#(id)""#)
        }
        if let rawID {
            fields.append(#""rawId":"\#(rawID)""#)
        }
        return Data("{\(fields.joined(separator: ","))}".utf8)
    }

    // MARK: - Parsing

    @Test(
        arguments: [
            ("AQ", [0x01]),
            ("AQI", [0x01, 0x02]),
            ("AQID", [0x01, 0x02, 0x03]),
            ("-__-AQ", [0xfb, 0xff, 0xfe, 0x01]),
        ] as [(String, [UInt8])]
    )
    func parsesCanonicalBase64URL(encoded: String, bytes: [UInt8]) {
        let id = CredentialID(base64URLEncoded: encoded)

        #expect(id == CredentialID(bytes: bytes))
        #expect(id?.base64URLEncoded.asString() == encoded)
    }

    @Test(arguments: CredentialIDTests.invalidEncodedIDs)
    func rejectsInvalidOrNonCanonicalBase64URL(encoded: String) {
        #expect(CredentialID(base64URLEncoded: encoded) == nil)
    }

    // MARK: - byteArray

    @Test(arguments: [[], [0x01], [0xfb, 0xff, 0xfe, 0x01]] as [[UInt8]])
    func byteArrayReturnsTheCredentialIDBytes(bytes: [UInt8]) {
        #expect(CredentialID(bytes: bytes).byteArray == bytes)
    }

    // MARK: - Codable

    private struct IDContainer: Codable {
        let id: CredentialID
    }

    @Test
    func encodesAsBase64URLString() throws {
        let container = IDContainer(id: CredentialID(bytes: [0xfb, 0xff, 0xfe, 0x01]))
        let encoded = try JSONEncoder().encode(container)

        #expect(String(decoding: encoded, as: UTF8.self) == #"{"id":"-__-AQ"}"#)
        #expect(try JSONDecoder().decode(IDContainer.self, from: encoded).id == container.id)
    }

    @Test(arguments: CredentialIDTests.invalidEncodedIDs)
    func decodingRejectsInvalidOrNonCanonicalBase64URL(encoded: String) throws {
        let data = try JSONEncoder().encode(["id": encoded])

        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(IDContainer.self, from: data)
        }
    }

    @Test
    func decodingRejectsNonStringValues() {
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(IDContainer.self, from: Data(#"{"id":[1,2,3]}"#.utf8))
        }
    }

    // MARK: - PublicKeyCredentialDescriptor

    @Test
    func descriptorRoundTripsCredentialID() throws {
        let descriptor = PublicKeyCredentialDescriptor(id: CredentialID(bytes: [0xfb, 0xff, 0xfe, 0x01]))
        let decoded = try JSONDecoder().decode(
            PublicKeyCredentialDescriptor.self,
            from: JSONEncoder().encode(descriptor)
        )

        #expect(decoded == descriptor)
    }

    @Test(arguments: CredentialIDTests.invalidEncodedIDs)
    func descriptorRejectsInvalidOrNonCanonicalIDs(encoded: String) throws {
        let data = try JSONEncoder().encode(["type": "public-key", "id": encoded])

        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(PublicKeyCredentialDescriptor.self, from: data)
        }
    }

    // MARK: - RegistrationCredential

    @Test
    func registrationCredentialEncodesTheSameIDToBothKeys() throws {
        let data = Self.json(id: "-__-AQ", rawID: "-__-AQ", response: Self.registrationResponse)
        let credential = try JSONDecoder().decode(RegistrationCredential.self, from: data)
        let encoded = try JSONDecoder().decode(EncodedIDs.self, from: JSONEncoder().encode(credential))

        #expect(credential.id == CredentialID(bytes: [0xfb, 0xff, 0xfe, 0x01]))
        #expect(encoded.id == "-__-AQ")
        #expect(encoded.rawId == "-__-AQ")
    }

    @Test(arguments: CredentialIDTests.invalidIDPairs)
    func registrationCredentialRejectsInvalidIDs(id: String, rawID: String) {
        let data = Self.json(id: id, rawID: rawID, response: Self.registrationResponse)

        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(RegistrationCredential.self, from: data)
        }
    }

    @Test(arguments: CredentialIDTests.missingIDPairs)
    func registrationCredentialRequiresBothIDs(id: String?, rawID: String?) {
        let data = Self.json(id: id, rawID: rawID, response: Self.registrationResponse)

        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(RegistrationCredential.self, from: data)
        }
    }

    // MARK: - AuthenticationCredential

    @Test
    func authenticationCredentialEncodesTheSameIDToBothKeys() throws {
        let data = Self.json(id: "-__-AQ", rawID: "-__-AQ", response: Self.authenticationResponse)
        let credential = try JSONDecoder().decode(AuthenticationCredential.self, from: data)
        let encoded = try JSONDecoder().decode(EncodedIDs.self, from: JSONEncoder().encode(credential))

        #expect(credential.id == CredentialID(bytes: [0xfb, 0xff, 0xfe, 0x01]))
        #expect(encoded.id == "-__-AQ")
        #expect(encoded.rawId == "-__-AQ")
    }

    @Test(arguments: CredentialIDTests.invalidIDPairs)
    func authenticationCredentialRejectsInvalidIDs(id: String, rawID: String) {
        let data = Self.json(id: id, rawID: rawID, response: Self.authenticationResponse)

        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(AuthenticationCredential.self, from: data)
        }
    }

    @Test(arguments: CredentialIDTests.missingIDPairs)
    func authenticationCredentialRequiresBothIDs(id: String?, rawID: String?) {
        let data = Self.json(id: id, rawID: rawID, response: Self.authenticationResponse)

        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(AuthenticationCredential.self, from: data)
        }
    }
}
