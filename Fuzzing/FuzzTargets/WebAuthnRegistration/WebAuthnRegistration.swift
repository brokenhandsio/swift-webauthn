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

import Foundation
import Fuzzing
import WebAuthn

let fuzzTargets: @Sendable () -> Void = {
    // The registration ceremony, entered where a relying party enters it: a JSON
    // body the browser POSTs, every byte of which the authenticator — or an
    // attacker holding one — controls.
    //
    // Two envelopes are built well-formed and only their payloads fuzzed. That
    // is not politeness, it is the difference between reaching the code under
    // test and not: `ParsedAuthenticatorAttestationResponse` decodes
    // clientDataJSON *before* the attestation object, so random bytes there
    // stop every execution before a single byte of CBOR is read. A first
    // version of this target did exactly that — 872,000 executions that never
    // once entered `AuthenticatorData.swift` or `CredentialPublicKey.swift`.
    //
    // So the challenge matches by construction and the client data parses,
    // which spends the budget where the interesting parsers are: CBOR, then the
    // authenticator data and COSE key inside it, then the attestation
    // statement whose `fmt` picks a verifier.
    FuzzTarget.structuredAsync("WebAuthnRegistration") { data in
        var data = data

        // Drawn from realistic sets rather than fuzzed freely: a client data
        // field that never matches is a field whose validation is the only
        // thing ever exercised. The wrong values are in the sets so that path
        // is still covered, just not exclusively. These come off the *back* of
        // the input, which is what leaves the front contiguous.
        let ceremonyType =
            data.element(of: ["webauthn.create", "webauthn.get", ""])
            ?? "webauthn.create"
        let origin =
            data.element(of: [
                "https://example.com", "http://example.com", "https://example.com:443",
                "https://evil.example.com", "",
            ]) ?? "https://example.com"

        // Fixed, deliberately. Neither is a parser under test — the credential
        // ID is length-checked and base64url'd, and the challenge only has to
        // match the copy placed in the client data, which it does by
        // construction. Holding them still means the whole of the front of the
        // input is the attestation object, so a seed is an attestation object
        // on disk followed by two bytes, one choosing the origin and then one
        // the ceremony type, rather than something reverse-engineered out of
        // the provider's draw order.
        let credentialID = [UInt8](repeating: 0x41, count: 16)
            .base64URLEncodedString().asString()
        let challenge: [UInt8] = [0x00, 0x01, 0x02, 0x03]
        let encodedChallenge = challenge.base64URLEncodedString().asString()

        // Everything left, which is the whole point: this is the CBOR carrying
        // the authenticator data, the COSE public key, and the attestation
        // statement whose `fmt` picks a verifier.
        let attestationObject = data.remainingBytes().base64URLEncodedString().asString()

        let clientDataJSON = """
            {"type":"\(ceremonyType)","challenge":"\(encodedChallenge)",\
            "origin":"\(origin)","crossOrigin":false}
            """
        let encodedClientData = Array(clientDataJSON.utf8).base64URLEncodedString().asString()

        let json = """
            {"id":"\(credentialID)","type":"public-key","rawId":"\(credentialID)",\
            "response":{"attestationObject":"\(attestationObject)",\
            "clientDataJSON":"\(encodedClientData)"}}
            """

        guard
            let credential = try? JSONDecoder()
                .decode(RegistrationCredential.self, from: Data(json.utf8))
        else { return }

        let manager = WebAuthnManager(
            configuration: .init(
                relyingPartyID: "example.com",
                relyingPartyName: "Example Relying Party",
                relyingPartyOrigin: "https://example.com"
            ))

        // Every legitimate rejection is a thrown error, so `try?` swallows all
        // of them. Anything that still stops the process is the finding: a
        // trap, a failed precondition, an unchecked index — a malformed
        // credential taking down the relying party that received it.
        _ = try? await manager.finishRegistration(
            challenge: challenge,
            credentialCreationData: credential,
            confirmCredentialIDNotRegisteredYet: { _ in true }
        )
    }
}
