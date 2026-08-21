//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2024 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

extension FixedWidthInteger {
    /// Initialize a fixed width integer from a contiguous sequence of Bytes representing a big endian type.
    /// - Parameter bigEndianBytes: The Bytes to interpret as a big endian integer.
    @inlinable
    init(bigEndianBytes: some Collection<UInt8>) {
        precondition(
            bigEndianBytes.count == MemoryLayout<Self>.size,
            "byte count (\(bigEndianBytes.count)) does not match MemoryLayout<Self>.size (\(MemoryLayout<Self>.size))"
        )
        var value: Self = 0
        for byte in bigEndianBytes {
            value = value &<< 8 | Self(truncatingIfNeeded: byte)
        }
        self = value
    }

    /// Initialize a fixed width integer from a contiguous sequence of Bytes representing a little endian type.
    /// - Parameter littleEndianBytes: The Bytes to interpret as a little endian integer.
    @inlinable
    init(littleEndianBytes: some BidirectionalCollection<UInt8>) {
        precondition(
            littleEndianBytes.count == MemoryLayout<Self>.size,
            "byte count (\(littleEndianBytes.count)) does not match MemoryLayout<Self>.size (\(MemoryLayout<Self>.size))"
        )
        var value: Self = 0
        for byte in littleEndianBytes.reversed() {
            value = value &<< 8 | Self(truncatingIfNeeded: byte)
        }
        self = value
    }
}
