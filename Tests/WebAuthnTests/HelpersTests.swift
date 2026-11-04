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

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Testing
@testable import WebAuthn

struct HelpersTests {
    @Test
    func base64URLEncodeReturnsCorrectString() {
        let input: [UInt8] = [1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0]
        let expectedBase64 = "AQABAAEBAAEAAQEAAAABAA=="
        let expectedBase64URL = "AQABAAEBAAEAAQEAAAABAA"

        let base64Encoded = input.base64EncodedString()
        let base64URLEncoded = input.base64URLEncodedString()

        #expect(expectedBase64 == base64Encoded.asString())
        #expect(expectedBase64URL == base64URLEncoded.asString())
    }

    @Test
    func encodeBase64Codable() throws {
        let base64 = EncodedBase64("AQABAAEBAAEAAQEAAAABAA==")
        let json = try JSONEncoder().encode(base64)
        let decodedBase64 = try JSONDecoder().decode(EncodedBase64.self, from: json)
        #expect(base64 == decodedBase64)
    }
    @Test(arguments: [
        ([UInt8](), "", ""),
        ([UInt8(0xfb)], "+w==", "-w"),
        ([UInt8(0xfb), 0xff], "+/8=", "-_8"),
        ([UInt8(0xfb), 0xff, 0xff], "+///", "-___"),
    ])
    func base64URLAlphabetAndPaddingRoundTrip(vector: ([UInt8], String, String)) {
        let (bytes, base64, base64URL) = vector
        #expect(EncodedBase64(base64).urlEncoded.asString() == base64URL)
        #expect(URLEncodedBase64(base64URL).urlDecoded.asString() == base64)
        #expect(URLEncodedBase64(base64URL).decodedBytes == bytes)
    }
    @Test
    func hexadecimalUsesLowercaseAndLeadingZeros() {
        #expect(Data([0, 15, 16, 255]).hexadecimal == "000f10ff")
    }
}
