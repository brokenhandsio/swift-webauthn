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

/// A CBOR map decoded once into its key/value pairs, with convenient keyed lookups.
///
/// `CBOR` values store maps lazily as raw bytes, so decoding the pairs on every access would be
/// wasteful. `CBORMap` decodes the pairs a single time and offers lookups by COSE integer label
/// (via a `CBOR` key) or by string key. A value that is not a CBOR map decodes to an empty map,
/// so all lookups simply return `nil`.
struct CBORMap {
    private let pairs: [CBORMapPair]

    init(_ cbor: CBOR) {
        // `mapValue()` re-decodes the pairs from the map's stored raw bytes. When `cbor` came
        // from `CBOR.decode`, that means the pairs are decoded twice (once inside `decode`,
        // once here) — an artifact of the library storing maps as lazy byte slices. Decoding
        // here a single time and reusing `pairs` avoids paying that cost on every lookup.
        pairs = (try? cbor.mapValue()) ?? []
    }

    /// The value for a map entry whose key equals `key` (e.g. a COSE integer label).
    subscript(key: CBOR) -> CBOR? {
        pairs.first { $0.key == key }?.value
    }

    /// The value for a string-keyed map entry.
    subscript(key: String) -> CBOR? {
        self[.textString(key)]
    }
}
