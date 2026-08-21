import Foundation
import Fuzzing
import WebAuthn

let fuzzTargets: @Sendable () -> Void = {
    // The assertion ceremony — the other half of WebAuthn, and a shorter path to
    // the same parsers. `finishAuthentication` is synchronous, so unlike the
    // registration target this one runs on libFuzzer's own thread and its crash
    // reports carry a stack.
    //
    // Two attacker-influenced surfaces meet here:
    //
    //   * `authenticatorData` arrives from the client, and reaches
    //     `AuthenticatorData.init` — the same parser registration uses, but
    //     without the AT flag, so a different set of branches.
    //   * `credentialPublicKey` is handed back by the relying party from its own
    //     storage, and goes straight into `CredentialPublicKey.init` — the
    //     function GHSA-6hhq-f689-wcc5 is about. Reaching it costs one CBOR
    //     decode here, against the four nested envelopes registration needs.
    FuzzTarget.structured("WebAuthnAuthentication") { data in
        let ceremonyType =
            data.element(of: ["webauthn.get", "webauthn.create", ""])
            ?? "webauthn.get"
        let origin =
            data.element(of: [
                "https://example.com", "http://example.com", "https://evil.example.com", "",
            ]) ?? "https://example.com"
        let signCount = data.integer(UInt32.self)

        // Drawn from the front, in order: the two payloads that matter.
        let credentialPublicKey = data.chunk()
        let signature = data.chunk()
        // Everything left, so a long authenticator data is reachable.
        let authenticatorData = data.remainingBytes()

        let credentialID = [UInt8](repeating: 0x41, count: 16)
            .base64URLEncodedString().asString()
        let challenge: [UInt8] = [0x00, 0x01, 0x02, 0x03]

        // Well-formed by construction, with the challenge matching, for the
        // reason the registration target documents: client data is verified
        // before anything interesting is parsed, so garbage here means the
        // budget is spent on one rejection path and nothing else.
        let clientDataJSON = """
            {"type":"\(ceremonyType)","challenge":"\(challenge.base64URLEncodedString().asString())",\
            "origin":"\(origin)","crossOrigin":false}
            """

        let json = """
            {"id":"\(credentialID)","type":"public-key","rawId":"\(credentialID)",\
            "response":{"clientDataJSON":"\(Array(clientDataJSON.utf8).base64URLEncodedString().asString())",\
            "authenticatorData":"\(authenticatorData.base64URLEncodedString().asString())",\
            "signature":"\(signature.base64URLEncodedString().asString())",\
            "userHandle":null}}
            """

        guard
            let credential = try? JSONDecoder()
                .decode(AuthenticationCredential.self, from: Data(json.utf8))
        else { return }

        let manager = WebAuthnManager(
            configuration: .init(
                relyingPartyID: "example.com",
                relyingPartyName: "Example Relying Party",
                relyingPartyOrigin: "https://example.com"
            ))

        // Every legitimate rejection throws. Anything that stops the process is
        // the finding.
        _ = try? manager.finishAuthentication(
            credential: credential,
            expectedChallenge: challenge,
            credentialPublicKey: credentialPublicKey,
            credentialCurrentSignCount: signCount
        )
    }
}
