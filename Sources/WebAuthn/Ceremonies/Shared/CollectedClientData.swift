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

/// A parsed version of the `clientDataJSON` received from the authenticator. The `clientDataJSON` is a
/// representation of the options we passed to the WebAuthn API (`.get()`/ `.create()`).
public struct CollectedClientData: Codable, Hashable, Sendable {
    enum CollectedClientDataVerifyError: Error {
        case ceremonyTypeDoesNotMatch
        case challengeDoesNotMatch
        case originDoesNotMatch
    }

    public struct CeremonyType: RawRepresentable, Equatable, Hashable, Codable, Sendable {
        public let rawValue: String
        
        public init?(rawValue: String) {
            switch rawValue {
            case "webauthn.create", "webauthn.get":
                self.rawValue = rawValue
            default:
                return nil
            }
        }
        
        private init(_ rawValue: String) {
            self.rawValue = rawValue
        }
        
        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            rawValue = try container.decode(String.self)
        }
        
        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(rawValue)
        }
        
        public static let create = CeremonyType("webauthn.create")
        public static let assert = CeremonyType("webauthn.get")
    }

    /// Contains the string "webauthn.create" when creating new credentials,
    /// and "webauthn.get" when getting an assertion from an existing credential
    public let type: CeremonyType
    /// The challenge that was provided by the Relying Party
    public let challenge: URLEncodedBase64
    public let origin: String

    func verify(storedChallenge: [UInt8], ceremonyType: CeremonyType, relyingPartyOrigin: String) throws(CollectedClientDataVerifyError) {
        guard type == ceremonyType else { throw .ceremonyTypeDoesNotMatch }
        guard challenge == storedChallenge.base64URLEncodedString() else {
            throw .challengeDoesNotMatch
        }
        guard origin == relyingPartyOrigin else { throw .originDoesNotMatch }
    }
}

extension CollectedClientData.CeremonyType: CustomStringConvertible {
    public var description: String { rawValue }
}
