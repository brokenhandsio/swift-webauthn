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
import Testing
@testable import WebAuthn

struct AuthenticatorSelectionTests {
    
    // MARK: - ResidentKeyRequirement Tests
    
    @Test
    func residentKeyRequirementValues() {
        #expect(ResidentKeyRequirement.required.rawValue == "required")
        #expect(ResidentKeyRequirement.preferred.rawValue == "preferred")
        #expect(ResidentKeyRequirement.discouraged.rawValue == "discouraged")
    }
    
    @Test
    func residentKeyRequirementEncoding() throws {
        let required = ResidentKeyRequirement.required
        let preferred = ResidentKeyRequirement.preferred
        let discouraged = ResidentKeyRequirement.discouraged
        
        let requiredJSON = try JSONEncoder().encode(required)
        let preferredJSON = try JSONEncoder().encode(preferred)
        let discouragedJSON = try JSONEncoder().encode(discouraged)
        
        let requiredString = String(data: requiredJSON, encoding: .utf8)
        let preferredString = String(data: preferredJSON, encoding: .utf8)
        let discouragedString = String(data: discouragedJSON, encoding: .utf8)
        
        #expect(requiredString == "\"required\"")
        #expect(preferredString == "\"preferred\"")
        #expect(discouragedString == "\"discouraged\"")
    }
    
    @Test
    func residentKeyRequirementDecoding() throws {
        let requiredJSON = "\"required\"".data(using: .utf8)!
        let preferredJSON = "\"preferred\"".data(using: .utf8)!
        let discouragedJSON = "\"discouraged\"".data(using: .utf8)!
        
        let required = try JSONDecoder().decode(ResidentKeyRequirement.self, from: requiredJSON)
        let preferred = try JSONDecoder().decode(ResidentKeyRequirement.self, from: preferredJSON)
        let discouraged = try JSONDecoder().decode(ResidentKeyRequirement.self, from: discouragedJSON)
        
        #expect(required == .required)
        #expect(preferred == .preferred)
        #expect(discouraged == .discouraged)
    }
    
    @Test
    func residentKeyRequirementRoundTrip() throws {
        let original = ResidentKeyRequirement.required
        let json = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ResidentKeyRequirement.self, from: json)
        #expect(original == decoded)
    }
    
    // MARK: - AuthenticatorSelection Tests
    
    @Test
    func authenticatorSelectionInitialization() {
        let selection = AuthenticatorSelection(
            authenticatorAttachment: .platform,
            residentKey: .required,
            userVerification: .preferred
        )
        
        #expect(selection.authenticatorAttachment == .platform)
        #expect(selection.residentKey == .required)
        #expect(selection.userVerification == .preferred)
    }
    
    @Test
    func authenticatorSelectionWithNilValues() {
        let selection = AuthenticatorSelection()
        
        #expect(selection.authenticatorAttachment == nil)
        #expect(selection.residentKey == nil)
        #expect(selection.userVerification == nil)
    }
    
    @Test
    func authenticatorSelectionEncoding() throws {
        let selection = AuthenticatorSelection(
            authenticatorAttachment: .platform,
            residentKey: .required,
            userVerification: .preferred
        )
        
        let json = try JSONEncoder().encode(selection)
        let jsonString = String(data: json, encoding: .utf8)!
        
        // Verify all fields are present
        #expect(jsonString.contains("platform"))
        #expect(jsonString.contains("required"))
        #expect(jsonString.contains("preferred"))
    }
    
    @Test
    func authenticatorSelectionDecoding() throws {
        let jsonString = """
        {
            "authenticatorAttachment": "platform",
            "residentKey": "required",
            "userVerification": "preferred"
        }
        """
        let json = jsonString.data(using: .utf8)!
        
        let selection = try JSONDecoder().decode(AuthenticatorSelection.self, from: json)
        
        #expect(selection.authenticatorAttachment == .platform)
        #expect(selection.residentKey == .required)
        #expect(selection.userVerification == .preferred)
    }
    
    @Test
    func authenticatorSelectionDecodingWithPartialFields() throws {
        let jsonString = """
        {
            "residentKey": "required"
        }
        """
        let json = jsonString.data(using: .utf8)!
        
        let selection = try JSONDecoder().decode(AuthenticatorSelection.self, from: json)
        
        #expect(selection.authenticatorAttachment == nil)
        #expect(selection.residentKey == .required)
        #expect(selection.userVerification == nil)
    }
    
    @Test
    func authenticatorSelectionRoundTrip() throws {
        let original = AuthenticatorSelection(
            authenticatorAttachment: .crossPlatform,
            residentKey: .preferred,
            userVerification: .required
        )
        
        let json = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(AuthenticatorSelection.self, from: json)
        
        #expect(decoded.authenticatorAttachment == original.authenticatorAttachment)
        #expect(decoded.residentKey == original.residentKey)
        #expect(decoded.userVerification == original.userVerification)
    }
    
    // MARK: - PublicKeyCredentialCreationOptions with AuthenticatorSelection Tests
    
    @Test
    func publicKeyCredentialCreationOptionsWithAuthenticatorSelection() {
        let user = PublicKeyCredentialUserEntity.mock
        let authenticatorSelection = AuthenticatorSelection(
            residentKey: .required,
            userVerification: .preferred
        )
        
        let options = PublicKeyCredentialCreationOptions(
            challenge: [1, 2, 3],
            user: user,
            relyingParty: PublicKeyCredentialRelyingPartyEntity(
                id: "example.com",
                name: "Example"
            ),
            publicKeyCredentialParameters: [PublicKeyCredentialParameters(type: .publicKey, alg: .algES256)],
            timeout: .seconds(60),
            attestation: .none,
            authenticatorSelection: authenticatorSelection
        )
        
        #expect(options.authenticatorSelection != nil)
        #expect(options.authenticatorSelection?.residentKey == .required)
        #expect(options.authenticatorSelection?.userVerification == .preferred)
    }
    
    @Test
    func publicKeyCredentialCreationOptionsWithoutAuthenticatorSelection() {
        let user = PublicKeyCredentialUserEntity.mock
        
        let options = PublicKeyCredentialCreationOptions(
            challenge: [1, 2, 3],
            user: user,
            relyingParty: PublicKeyCredentialRelyingPartyEntity(
                id: "example.com",
                name: "Example"
            ),
            publicKeyCredentialParameters: [PublicKeyCredentialParameters(type: .publicKey, alg: .algES256)],
            timeout: .seconds(60),
            attestation: .none
        )
        
        #expect(options.authenticatorSelection == nil)
    }
    
    @Test
    func publicKeyCredentialCreationOptionsEncodingWithAuthenticatorSelection() throws {
        let user = PublicKeyCredentialUserEntity.mock
        let authenticatorSelection = AuthenticatorSelection(
            residentKey: .required,
            userVerification: .preferred
        )
        
        let options = PublicKeyCredentialCreationOptions(
            challenge: [1, 2, 3],
            user: user,
            relyingParty: PublicKeyCredentialRelyingPartyEntity(
                id: "example.com",
                name: "Example"
            ),
            publicKeyCredentialParameters: [PublicKeyCredentialParameters(type: .publicKey, alg: .algES256)],
            timeout: .seconds(60),
            attestation: .none,
            authenticatorSelection: authenticatorSelection
        )
        
        let json = try JSONEncoder().encode(options)
        let jsonString = String(data: json, encoding: .utf8)!
        
        // Verify authenticatorSelection is included
        #expect(jsonString.contains("authenticatorSelection"))
        #expect(jsonString.contains("residentKey"))
        #expect(jsonString.contains("required"))
        #expect(jsonString.contains("userVerification"))
        #expect(jsonString.contains("preferred"))
    }
    
    @Test
    func publicKeyCredentialCreationOptionsDecodingWithAuthenticatorSelection() throws {
        let jsonString = """
        {
            "challenge": "AQID",
            "rp": {
                "id": "example.com",
                "name": "Example"
            },
            "user": {
                "id": "AQID",
                "name": "John",
                "displayName": "Johnny"
            },
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "attestation": "none",
            "authenticatorSelection": {
                "residentKey": "required",
                "userVerification": "preferred"
            }
        }
        """
        let json = jsonString.data(using: .utf8)!
        
        let options = try JSONDecoder().decode(PublicKeyCredentialCreationOptions.self, from: json)
        
        #expect(options.authenticatorSelection != nil)
        #expect(options.authenticatorSelection?.residentKey == .required)
        #expect(options.authenticatorSelection?.userVerification == .preferred)
    }
    
    // MARK: - WebAuthnManager.beginRegistration with AuthenticatorSelection Tests
    
    @Test
    func beginRegistrationWithAuthenticatorSelection() {
        let configuration = WebAuthnManager.Configuration(
            relyingPartyID: "example.com",
            relyingPartyName: "Example",
            relyingPartyOrigin: "https://example.com"
        )
        let challenge: [UInt8] = [1, 2, 3]
        let webAuthnManager = WebAuthnManager(
            configuration: configuration,
            challengeGenerator: .mock(generate: challenge)
        )
        
        let user = PublicKeyCredentialUserEntity.mock
        let authenticatorSelection = AuthenticatorSelection(
            residentKey: .required,
            userVerification: .preferred
        )
        
        let options = webAuthnManager.beginRegistration(
            user: user,
            authenticatorSelection: authenticatorSelection
        )
        
        #expect(options.authenticatorSelection != nil)
        #expect(options.authenticatorSelection?.residentKey == .required)
        #expect(options.authenticatorSelection?.userVerification == .preferred)
        #expect(options.challenge == challenge)
        #expect(options.user.id == user.id)
    }
    
    @Test
    func beginRegistrationWithoutAuthenticatorSelection() {
        let configuration = WebAuthnManager.Configuration(
            relyingPartyID: "example.com",
            relyingPartyName: "Example",
            relyingPartyOrigin: "https://example.com"
        )
        let challenge: [UInt8] = [1, 2, 3]
        let webAuthnManager = WebAuthnManager(
            configuration: configuration,
            challengeGenerator: .mock(generate: challenge)
        )
        
        let user = PublicKeyCredentialUserEntity.mock
        
        let options = webAuthnManager.beginRegistration(user: user)
        
        #expect(options.authenticatorSelection == nil)
        #expect(options.challenge == challenge)
        #expect(options.user.id == user.id)
    }
}

