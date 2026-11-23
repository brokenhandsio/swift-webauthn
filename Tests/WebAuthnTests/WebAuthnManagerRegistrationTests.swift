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

import CBOR
import Testing

@testable import WebAuthn

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

struct WebAuthnManagerRegistrationTests {
    var webAuthnManager: WebAuthnManager!

    let challenge: [UInt8] = [1, 0, 1]
    let relyingPartyDisplayName = "Testy test"
    let relyingPartyID = "example.com"
    let relyingPartyOrigin = "https://example.com"

    init() {
        let configuration = WebAuthnManager.Configuration(
            relyingPartyID: relyingPartyID,
            relyingPartyName: relyingPartyDisplayName,
            relyingPartyOrigin: relyingPartyOrigin
        )
        webAuthnManager = .init(configuration: configuration, challengeGenerator: .mock(generate: challenge))
    }

    @Test
    func registrationCredentialIsCodable() async throws {
        let json = """
            {
              "type": "public-key",
              "rawId": "AQEBAQEBAQEBAQ",
              "response": {
                "clientDataJSON": "eyJyYW5kb21PdGhlcktleSI6IjEyMyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm9yaWdpbiI6Imh0dHBzOlwvXC9leGFtcGxlLmNvbSIsImNoYWxsZW5nZSI6IkFBQUFBQUEifQ",
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViFo3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUdFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQGlAQIDJiABIVggliG0CSKktS9RPBtmebjUj4EBmXLH88ZNbIVt405FpkUiWCBmNzEq_grpor7Ai89GEeDpCB5vEgMRqJhmBdXTtLJI-A"
              },
              "id": "AQEBAQEBAQEBAQ"
            }
            """.utf8
        let sut = try JSONDecoder().decode(RegistrationCredential.self, from: Data(json))
        let data = try JSONEncoder().encode(sut)

        #expect(throws: Never.self, "All RegistrationCredential's properties were encoded") {
            try JSONDecoder().decode(RegistrationCredential.self, from: data)
        }
    }

    // MARK: - beginRegistration()
    @Test
    func beginRegistrationReturns() {
        let user = PublicKeyCredentialUserEntity.mock
        let publicKeyCredentialParameter = PublicKeyCredentialParameters(type: .publicKey, alg: .algES256)
        let options = webAuthnManager.beginRegistration(
            user: user,
            publicKeyCredentialParameters: [publicKeyCredentialParameter]
        )

        #expect(options.challenge == challenge)
        #expect(options.relyingParty.id == relyingPartyID)
        #expect(options.relyingParty.name == relyingPartyDisplayName)
        #expect(options.user.id == user.id)
        #expect(options.user.displayName == user.displayName)
        #expect(options.user.name == user.name)
        #expect(options.publicKeyCredentialParameters == [publicKeyCredentialParameter])
    }

    // MARK: - finishRegistration()

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsIfCeremonyTypeDoesNotMatch(keyConfiguration: TestKeyConfiguration) async throws {
        var clientDataJSON = TestClientDataJSON()
        clientDataJSON.type = "webauthn.get"
        await #expect(throws: CollectedClientData.CollectedClientDataVerifyError.ceremonyTypeDoesNotMatch) {
            try await finishRegistration(
                clientDataJSON: clientDataJSON.jsonBytes,
                attestationObject: keyConfiguration.attestationObject
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsIfChallengeDoesNotMatch(keyConfiguration: TestKeyConfiguration) async throws {
        var clientDataJSON = TestClientDataJSON()
        clientDataJSON.challenge = [0, 2, 4].base64URLEncodedString()
        await #expect(throws: CollectedClientData.CollectedClientDataVerifyError.challengeDoesNotMatch) {
            try await finishRegistration(
                challenge: [UInt8]("definitely another challenge".utf8),
                clientDataJSON: clientDataJSON.jsonBytes,
                attestationObject: keyConfiguration.attestationObject
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsIfOriginDoesNotMatch(keyConfiguration: TestKeyConfiguration) async throws {
        var clientDataJSON = TestClientDataJSON()
        clientDataJSON.origin = "https://random-origin.org"
        // `webAuthnManager` is configured with origin = https://example.com
        await #expect(throws: CollectedClientData.CollectedClientDataVerifyError.originDoesNotMatch) {
            try await finishRegistration(
                clientDataJSON: clientDataJSON.jsonBytes,
                attestationObject: keyConfiguration.attestationObject
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsWithInvalidCredentialCreationType(keyConfiguration: TestKeyConfiguration) async throws {
        await #expect(throws: WebAuthnError.invalidCredentialCreationType) {
            try await finishRegistration(
                type: "foo",
                attestationObject: keyConfiguration.attestationObject
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsIfClientDataJSONDecodingFails(keyConfiguration: TestKeyConfiguration) async throws {
        await #expect(throws: DecodingError.self) {
            try await finishRegistration(
                clientDataJSON: [0],
                attestationObject: keyConfiguration.attestationObject
            )
        }
    }

    @Test
    func finishRegistrationFailsIfAttestationObjectIsNotBase64() async throws {
        await #expect(throws: WebAuthnError.invalidAttestationObject) {
            try await finishRegistration(attestationObject: [])
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsIfAuthDataIsInvalid(keyConfiguration: TestKeyConfiguration) async throws {
        await #expect(throws: WebAuthnError.invalidAuthData) {
            try await finishRegistration(
                attestationObject: keyConfiguration.attestationObjectBuilder
                    .invalidAuthData()
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsIfFmtIsInvalid(keyConfiguration: TestKeyConfiguration) async throws {
        await #expect(throws: WebAuthnError.invalidFmt) {
            try await finishRegistration(
                attestationObject: keyConfiguration.attestationObjectBuilder
                    .invalidFmt()
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsIfAttStmtIsMissing(keyConfiguration: TestKeyConfiguration) async throws {
        await #expect(throws: WebAuthnError.missingAttStmt) {
            try await finishRegistration(
                attestationObject: keyConfiguration.attestationObjectBuilder
                    .missingAttStmt()
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsIfAuthDataIsTooShort(keyConfiguration: TestKeyConfiguration) async throws {
        await #expect(throws: WebAuthnError.authDataTooShort) {
            try await finishRegistration(
                attestationObject: keyConfiguration.attestationObjectBuilder
                    .zeroAuthData(byteCount: 36)
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsIfAttestedCredentialDataFlagIsSetButThereIsNoCredentialData(keyConfiguration: TestKeyConfiguration)
        async throws
    {
        await #expect(throws: WebAuthnError.attestedCredentialDataMissing) {
            try await finishRegistration(
                attestationObject: keyConfiguration.attestationObjectBuilder
                    .authData {
                        $0
                            .flags(0b01000001)
                            .noAttestedCredentialData()
                            .noExtensionData()
                    }
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsIfAttestedCredentialDataFlagIsNotSetButThereIsCredentialData(keyConfiguration: TestKeyConfiguration)
        async throws
    {
        await #expect(throws: WebAuthnError.attestedCredentialFlagNotSet) {
            try await finishRegistration(
                attestationObject: keyConfiguration.attestationObjectBuilder
                    .authData {
                        $0
                            .flags(0b00000001)
                            .attestedCredData(credentialPublicKey: [])
                    }
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsIfExtensionDataFlagIsSetButThereIsNoExtensionData(keyConfiguration: TestKeyConfiguration) async throws {
        await #expect(throws: WebAuthnError.extensionDataMissing) {
            try await finishRegistration(
                attestationObject: keyConfiguration.attestationObjectBuilder
                    .authData { $0.noExtensionData().flags(0b11000001) }
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsIfCredentialIdIsTooShort(keyConfiguration: TestKeyConfiguration) async throws {
        await #expect(throws: WebAuthnError.credentialIDTooShort) {
            try await finishRegistration(
                attestationObject: keyConfiguration.attestationObjectBuilder
                    .authData {
                        $0
                            .attestedCredData(
                                credentialIDLength: [0b00000000, 0b00000010],  // we expect length = 2
                                credentialID: [255],  // but only get length = 1
                                credentialPublicKey: []
                            )
                            .noExtensionData()
                    }
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsIfRelyingPartyIDHashDoesNotMatch(keyConfiguration: TestKeyConfiguration) async throws {
        await #expect(throws: WebAuthnError.relyingPartyIDHashDoesNotMatch) {
            try await finishRegistration(
                attestationObject: keyConfiguration.attestationObjectBuilder
                    .authData { $0.relyingPartyIDHash(fromRelyingPartyID: "invalid-id.com") }
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsIfUserPresentFlagIsNotSet(keyConfiguration: TestKeyConfiguration) async throws {
        await #expect(throws: WebAuthnError.userPresentFlagNotSet) {
            try await finishRegistration(
                attestationObject: keyConfiguration.attestationObjectBuilder
                    .authData { $0.flags(0b11000000) }
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsIfUserVerificationFlagIsNotSetButRequired(keyConfiguration: TestKeyConfiguration) async throws {
        await #expect(throws: WebAuthnError.userVerificationRequiredButFlagNotSet) {
            try await finishRegistration(
                attestationObject: keyConfiguration.attestationObjectBuilder
                    .authData { $0.flags(0b11000001) }
                    .build()
                    .cborEncoded,
                requireUserVerification: true
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsIfAttFmtIsNoneButAttStmtIsIncluded(keyConfiguration: TestKeyConfiguration) async throws {
        await #expect(throws: WebAuthnError.attestationStatementMustBeEmpty) {
            try await finishRegistration(
                attestationObject: keyConfiguration.attestationObjectBuilder
                    .fmt("none")
                    .attStmt(.double(123))
                    .build()
                    .cborEncoded,
                requireUserVerification: true
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationFailsIfIDIsTooLong(keyConfiguration: TestKeyConfiguration) async throws {
        await #expect(throws: WebAuthnError.credentialIDTooLong) {
            try await finishRegistration(
                credentialID: CredentialID(bytes: [UInt8](repeating: 0, count: 1024)),
                attestationObject: keyConfiguration.attestationObject
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishAuthenticationFailsIfCredentialIDTooLong(keyConfiguration: TestKeyConfiguration) async throws {
        /// This should succeed as it's on the border of being acceptable
        _ = try await finishRegistration(
            credentialID: CredentialID(bytes: [UInt8](repeating: 0, count: 1023)),
            attestationObject: keyConfiguration.attestationObjectBuilder
                .authData {
                    $0
                        .attestedCredData(
                            credentialIDLength: [0b000_00011, 0b1111_1111],
                            credentialID: Array(repeating: 0, count: 1023),
                            credentialPublicKey: keyConfiguration.credentialPublicKey
                        )
                }
                .build()
                .cborEncoded
        )

        /// While this one should throw
        await #expect(throws: WebAuthnError.credentialIDTooLong) {
            try await finishRegistration(
                attestationObject: keyConfiguration.attestationObjectBuilder
                    .authData {
                        $0
                            .attestedCredData(
                                credentialIDLength: [0b000_00100, 0b0000_0000],
                                credentialID: Array(repeating: 0, count: 1024),
                                credentialPublicKey: keyConfiguration.credentialPublicKey
                            )
                    }
                    .build()
                    .cborEncoded
            )
        }
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationSucceeds(keyConfiguration: TestKeyConfiguration) async throws {
        let credentialID = CredentialID(bytes: [0b00000001])
        let credentialPublicKey: [UInt8] = keyConfiguration.credentialPublicKey
        let authData = keyConfiguration.authDataBuilder
            .attestedCredData(credentialPublicKey: credentialPublicKey)
            .noExtensionData()
        let attestationObject = keyConfiguration.attestationObjectBuilder
            .authData(authData)
            .build()
            .cborEncoded

        let credential = try await finishRegistration(
            credentialID: credentialID,
            attestationObject: attestationObject
        )

        #expect(credential.id == credentialID)
        #expect(credential.publicKey == credentialPublicKey)
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func credentialAAGUIDAccessorReturnsCorrectValue(keyConfiguration: TestKeyConfiguration) async throws {
        let testAAGUID = AAGUID(uuidString: "dd4ec289-e01d-41c9-bb89-70fa845d4bf2")!
        let credentialID = CredentialID(bytes: [0b00000001])
        let credentialPublicKey: [UInt8] = keyConfiguration.credentialPublicKey
        let authData = keyConfiguration.authDataBuilder
            .attestedCredData(
                authenticatorAttestationGUID: testAAGUID,
                credentialPublicKey: credentialPublicKey
            )
            .noExtensionData()
        let attestationObject = keyConfiguration.attestationObjectBuilder
            .authData(authData)
            .build()
            .cborEncoded

        let credential = try await finishRegistration(
            credentialID: credentialID,
            attestationObject: attestationObject
        )

        // Test that credential.aaguid returns the correct AAGUID
        #expect(credential.aaguid != nil)
        #expect(credential.aaguid?.id == testAAGUID.id)
        #expect(credential.aaguid?.bytes == testAAGUID.bytes)

        // Test that credential.attestationObject.aaguid returns the same value
        #expect(credential.attestationObject.aaguid != nil)
        #expect(credential.attestationObject.aaguid?.id == testAAGUID.id)
        #expect(credential.attestationObject.aaguid?.bytes == testAAGUID.bytes)

        // Verify they return the same value
        #expect(credential.aaguid == credential.attestationObject.aaguid)
    }

    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func credentialAAGUIDAccessorReturnsAnonymousByDefault(keyConfiguration: TestKeyConfiguration) async throws {
        // When no AAGUID is specified, it defaults to .anonymous
        let credentialID = CredentialID(bytes: [0b00000001])
        let credentialPublicKey: [UInt8] = keyConfiguration.credentialPublicKey
        let authData = keyConfiguration.authDataBuilder
            .attestedCredData(credentialPublicKey: credentialPublicKey)  // Uses .anonymous by default
            .noExtensionData()
        let attestationObject = keyConfiguration.attestationObjectBuilder
            .authData(authData)
            .build()
            .cborEncoded

        let credential = try await finishRegistration(
            credentialID: credentialID,
            attestationObject: attestationObject
        )

        // Test that credential.aaguid returns the anonymous AAGUID
        #expect(credential.aaguid != nil)
        #expect(credential.aaguid == .anonymous)
        #expect(credential.aaguid?.bytes == Array(repeating: 0, count: 16))
    }

    // A credential public key consisting of the single byte 0x04 used to crash
    // the relying party. CBOR reads 0x04 as the integer 4, so the key "decoded",
    // and a branch meant for raw U2F keys then sliced bytes 1...65 out of a
    // one-byte array. It must be rejected with an error instead.
    @Test(arguments: [
        TestKeyConfiguration.ecdsa,
        TestKeyConfiguration.rsa,
    ])
    func finishRegistrationRejectsOneByteCredentialPublicKey(keyConfiguration: TestKeyConfiguration) async throws {
        await #expect(throws: WebAuthnError.invalidKeyType) {
            try await finishRegistration(
                attestationObject: keyConfiguration.attestationObjectBuilder
                    .authData { $0.attestedCredData(credentialPublicKey: [0x04]) }
                    .build()
                    .cborEncoded
            )
        }
    }

    // The attestation object from the input the registration fuzz target saved
    // when it found that crash (crash-7ec20b87e8874653d7eab00fd3fbfc0c1cb6b140,
    // minus the 2 trailing bytes the harness spends choosing the ceremony type
    // and origin). The file is named for the input as found, before it was
    // translated to swift-fuzz 1.0's layout, which spends 14 fewer bytes on
    // those choices. It is the `extensions` seed with the credential public key's
    // first byte changed from 0xa5 to 0x04. Because the extension-data flag is
    // set, the rest of the original key is accepted as extension data, so a
    // one-byte change was enough to reach the crash.
    @Test
    func finishRegistrationRejectsFuzzerCrash7ec20b87() async throws {
        let attestationObject = """
            a363666d74646e6f6e656761747453746d74a06861757468446174615895a379a6f6eeafb9a55e378c118034e2751e68
            2fab9f2d30ab13d2125586ce1947c10000000000000000000000000000000000000000001041414141414141fbfbfbfb
            fbfbfbfb05040402fbfb565656565656565656565656575656fb0b0c0d0e0f101112131415161718191a1b1c1d1e1f22
            5820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fa0
            """.filter { !$0.isWhitespace }.hexadecimal!
        await #expect(throws: WebAuthnError.invalidKeyType) {
            try await finishRegistration(attestationObject: attestationObject)
        }
    }

    @Test
    func finishRegistrationFuzzying() async throws {
        for _ in 1...50 {
            let length = Int.random(in: 1...10_000_000)
            let randomAttestationObject = Array(repeating: UInt8.random(), count: length)
            let shouldBeNil = try? await finishRegistration(attestationObject: randomAttestationObject)
            #expect(shouldBeNil == nil)
        }
    }

    private func finishRegistration(
        challenge: [UInt8] = TestConstants.mockChallenge,
        type: CredentialType = .publicKey,
        credentialID: CredentialID = CredentialID(bytes: [0b00000001]),
        clientDataJSON: [UInt8] = TestClientDataJSON().jsonBytes,
        attestationObject: [UInt8],
        requireUserVerification: Bool = false,
        confirmCredentialIDNotRegisteredYet: (CredentialID) async throws -> Bool = { _ in true }
    ) async throws -> Credential {
        try await webAuthnManager.finishRegistration(
            challenge: challenge,
            credentialCreationData: RegistrationCredential(
                id: credentialID,
                type: type,
                attestationResponse: AuthenticatorAttestationResponse(
                    clientDataJSON: clientDataJSON,
                    attestationObject: attestationObject
                )
            ),
            requireUserVerification: requireUserVerification,
            confirmCredentialIDNotRegisteredYet: confirmCredentialIDNotRegisteredYet
        )
    }
}
