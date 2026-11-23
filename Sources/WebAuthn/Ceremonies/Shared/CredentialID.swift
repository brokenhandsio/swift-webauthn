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

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

public struct CredentialID: Hashable, Sendable {
    private let storage: ContiguousArray<UInt8>

    public init(bytes: some Sequence<UInt8>) {
        self.storage = ContiguousArray(bytes)
    }

    /// Creates a credential ID from its canonical, unpadded base64url encoding.
    ///
    /// Returns `nil` if `string` is invalid or is a non-canonical encoding of the bytes it decodes to.
    public init?(base64URLEncoded string: String) {
        let encoded = URLEncodedBase64(string)
        guard let bytes = encoded.decodedBytes, bytes.base64URLEncodedString() == encoded else {
            return nil
        }
        self.init(bytes: bytes)
    }

    public var bytes: Span<UInt8> {
        @_lifetime(borrow self)
        borrowing get { storage.span }
    }

    public var base64URLEncoded: URLEncodedBase64 {
        EncodedBase64(Data(storage).base64EncodedString()).urlEncoded
    }
}
