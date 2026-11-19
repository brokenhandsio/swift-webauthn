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

import Testing

@testable import WebAuthn

struct CredentialPublicKeyTests {
    // Every input of up to two bytes, which is where a short-input indexing bug
    // like the old U2F branch (a one-byte 0x04 key sliced as if it were 65 bytes)
    // lives. None is a valid COSE key, so each must throw; a trap instead takes
    // the whole test run down, which is the point.
    @Test
    func shortInputsAreRejectedWithoutTrapping() {
        var accepted: [[UInt8]] = []
        func check(_ input: [UInt8]) {
            if (try? CredentialPublicKey(publicKeyBytes: input)) != nil { accepted.append(input) }
        }
        check([])
        for first in UInt8.min...UInt8.max {
            check([first])
            for second in UInt8.min...UInt8.max {
                check([first, second])
            }
        }
        #expect(accepted.isEmpty, "accepted as keys: \(accepted.prefix(5))")
    }
}
