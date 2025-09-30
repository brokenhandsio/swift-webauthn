//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2023 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation

/// On successful authentication, this structure contains a summary of the authentication flow
public struct VerifiedAuthentication: Sendable {
    public struct CredentialDeviceType: RawRepresentable, Equatable, Hashable, Codable, Sendable {
        public let rawValue: String
        
        public init?(rawValue: String) {
            switch rawValue {
            case "single_device", "multi_device":
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
        
        public static let singleDevice = CredentialDeviceType("single_device")
        public static let multiDevice = CredentialDeviceType("multi_device")
    }

    /// The credential id associated with the public key
    public let credentialID: URLEncodedBase64
    /// The updated sign count after the authentication ceremony
    public let newSignCount: UInt32
    /// Whether the authenticator is a single- or multi-device authenticator. This value is determined after
    /// registration and will not change afterwards.
    public let credentialDeviceType: CredentialDeviceType
    /// Whether the authenticator is known to be backed up currently
    public let credentialBackedUp: Bool
}

extension VerifiedAuthentication.CredentialDeviceType: CustomStringConvertible {
    public var description: String { rawValue }
}
