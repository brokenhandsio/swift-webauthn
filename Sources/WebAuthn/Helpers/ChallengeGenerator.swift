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

public struct ChallengeGenerator: Sendable {
    public var generate: @Sendable () -> [UInt8]

    public init(generate: @Sendable @escaping () -> [UInt8]) {
        self.generate = generate
    }
  
    public static var live: Self {
        .init(generate: { [UInt8].random(count: 32) })
    }
}
