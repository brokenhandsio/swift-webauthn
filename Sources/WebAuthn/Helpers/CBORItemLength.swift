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

import CBOR

/// Errors thrown while scanning a CBOR data item.
enum CBORScanError: Error {
    case truncated
    case unsupported
    /// The item is nested deeper than the allowed maximum.
    case tooDeep
}

/// The maximum nesting depth permitted when decoding CBOR.
///
/// The underlying CBOR decoder recurses without a depth limit, so deeply nested input can
/// exhaust the stack. We bound the depth before decoding to protect against hostile input,
/// matching the limit used previously with `CBOROptions(maximumDepth:)`.
let cborMaximumDepth = 16

/// Decode a single top-level CBOR item, rejecting input nested deeper than `maximumDepth`.
///
/// The depth is validated with `cborFirstItemLength` before handing the bytes to the library
/// decoder, which has no depth limit of its own. This prevents a stack overflow on hostile or
/// malformed input.
///
/// Note: this deliberately walks the input twice — once to bound the depth (a cheap,
/// allocation-free scan) and once in `CBOR.decode`. The duplicate pass is the price of the
/// missing depth option upstream; for WebAuthn-sized payloads the overhead is negligible.
func decodeCBOR(_ bytes: [UInt8], maximumDepth: Int = cborMaximumDepth) throws -> CBOR {
    _ = try cborFirstItemLength(bytes[...], maximumDepth: maximumDepth)
    return try CBOR.decode(bytes)
}

/// Returns the byte length of the first complete CBOR data item at the start of `bytes`.
///
/// This walks the CBOR structure (RFC 8949) without materializing the decoded value, so the
/// caller can learn how many bytes a single item occupies — for example to separate a COSE
/// public key from any trailing extension data. It replaces the streaming `decodeItem()`
/// mechanism that earlier CBOR libraries exposed, and bounds recursion to `maximumDepth`.
func cborFirstItemLength(_ bytes: ArraySlice<UInt8>, maximumDepth: Int = cborMaximumDepth) throws -> Int {
    var cursor = 0 // offset from the start of `bytes`

    func byte() throws -> UInt8 {
        guard cursor < bytes.count else { throw CBORScanError.truncated }
        let value = bytes[bytes.startIndex + cursor]
        cursor += 1
        return value
    }

    func skip(_ n: UInt64) throws {
        guard n <= UInt64(Int.max), cursor + Int(n) <= bytes.count else { throw CBORScanError.truncated }
        cursor += Int(n)
    }

    /// Read the additional-information argument for a major type, advancing the cursor
    /// past any extended length bytes.
    func readArgument(_ additional: UInt8) throws -> UInt64 {
        switch additional {
        case 0...23:
            return UInt64(additional)
        case 24:
            return UInt64(try byte())
        case 25:
            var value: UInt64 = 0
            for _ in 0..<2 { value = (value << 8) | UInt64(try byte()) }
            return value
        case 26:
            var value: UInt64 = 0
            for _ in 0..<4 { value = (value << 8) | UInt64(try byte()) }
            return value
        case 27:
            var value: UInt64 = 0
            for _ in 0..<8 { value = (value << 8) | UInt64(try byte()) }
            return value
        default:
            // 28...30 are reserved; 31 (indefinite) is handled by the callers directly.
            throw CBORScanError.unsupported
        }
    }

    /// Peek for an indefinite-length break (0xFF), consuming it when present.
    func consumeBreak() throws -> Bool {
        guard cursor < bytes.count else { throw CBORScanError.truncated }
        if bytes[bytes.startIndex + cursor] == 0xFF {
            cursor += 1
            return true
        }
        return false
    }

    func scanItem(depth: Int) throws {
        guard depth <= maximumDepth else { throw CBORScanError.tooDeep }

        let initial = try byte()
        let majorType = initial >> 5
        let additional = initial & 0x1F

        switch majorType {
        case 0, 1: // unsigned / negative integer
            _ = try readArgument(additional)
        case 2, 3: // byte string / text string
            if additional == 31 {
                // Indefinite length: a sequence of definite-length chunks until break.
                while true {
                    let next = try byte()
                    if next == 0xFF { break } // break stop code
                    guard next >> 5 == majorType else { throw CBORScanError.unsupported }
                    try skip(try readArgument(next & 0x1F))
                }
            } else {
                try skip(try readArgument(additional))
            }
        case 4: // array
            if additional == 31 {
                while try !consumeBreak() { try scanItem(depth: depth + 1) }
            } else {
                let count = try readArgument(additional)
                for _ in 0..<count { try scanItem(depth: depth + 1) }
            }
        case 5: // map
            if additional == 31 {
                while try !consumeBreak() { try scanItem(depth: depth + 1); try scanItem(depth: depth + 1) }
            } else {
                let count = try readArgument(additional)
                for _ in 0..<count { try scanItem(depth: depth + 1); try scanItem(depth: depth + 1) }
            }
        case 6: // tag
            _ = try readArgument(additional)
            try scanItem(depth: depth + 1)
        case 7: // simple values / floats
            switch additional {
            case 0...23: break          // simple value encoded in the initial byte
            case 24: _ = try byte()     // simple value in the following byte
            case 25: try skip(2)        // half-precision float
            case 26: try skip(4)        // single-precision float
            case 27: try skip(8)        // double-precision float
            default: throw CBORScanError.unsupported
            }
        default:
            throw CBORScanError.unsupported
        }
    }

    try scanItem(depth: 1)
    return cursor
}
