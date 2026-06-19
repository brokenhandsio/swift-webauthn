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

@testable import WebAuthn
import CBOR

struct TestCredentialPublicKey {
    var kty: CBOR?
    var alg: CBOR?
    // EC2, OKP
    var crv: CBOR?
    var xCoordinate: CBOR?
    
    //EC2
    var yCoordinate: CBOR?

    // RSA
    var nCoordinate: CBOR?
    var eCoordinate: CBOR?

    var byteArrayRepresentation: [UInt8] {
        var pairs: [CBORMapPair] = []
        if let kty {
            pairs.append(CBORMapPair(key: COSEKey.kty.cbor, value: kty))
        }
        if let alg {
            pairs.append(CBORMapPair(key: COSEKey.alg.cbor, value: alg))
        }
        if let crv {
            pairs.append(CBORMapPair(key: COSEKey.crv.cbor, value: crv))
        }
        if let xCoordinate {
            pairs.append(CBORMapPair(key: COSEKey.x.cbor, value: xCoordinate))
        }
        if let yCoordinate {
            pairs.append(CBORMapPair(key: COSEKey.y.cbor, value: yCoordinate))
        }

        if let nCoordinate {
            pairs.append(CBORMapPair(key: COSEKey.n.cbor, value: nCoordinate))
        }

        if let eCoordinate {
            pairs.append(CBORMapPair(key: COSEKey.e.cbor, value: eCoordinate))
        }

        return CBOR.map(pairs).encode()
    }
}

struct TestCredentialPublicKeyBuilder {
    var wrapped: TestCredentialPublicKey

    init(wrapped: TestCredentialPublicKey = TestCredentialPublicKey()) {
        self.wrapped = wrapped
    }

    func buildAsByteArray() -> [UInt8] {
        return wrapped.byteArrayRepresentation
    }

    func validMockECDSA() -> Self {
        return self
            .kty(.ellipticKey)
            .crv(.p256)
            .alg(.algES256)
            .xCoordinate(TestECCKeyPair.publicKeyXCoordinate)
            .yCoordiante(TestECCKeyPair.publicKeyYCoordinate)
    }
    
    func validMockRSA() -> Self {
        return self
            .kty(.rsaKey)
            .alg(.algRS256)
            .nCoordinate(TestRSAKeyPair.publicKeyNCoordinate)
            .eCoordiante(TestRSAKeyPair.publicKeyECoordinate)
    }


    func kty(_ kty: COSEKeyType) -> Self {
        var temp = self
        temp.wrapped.kty = .unsignedInt(kty.rawValue)
        return temp
    }

    func crv(_ crv: COSECurve) -> Self {
        var temp = self
        temp.wrapped.crv = .unsignedInt(crv.rawValue)
        return temp
    }

    func alg(_ alg: COSEAlgorithmIdentifier) -> Self {
        var temp = self
        temp.wrapped.alg = .negativeInt(Int64(alg.rawValue))
        return temp
    }

    func xCoordinate(_ xCoordinate: [UInt8]) -> Self {
        var temp = self
        temp.wrapped.xCoordinate = .byteString(ArraySlice(xCoordinate))
        return temp
    }

    func yCoordiante(_ yCoordinate: [UInt8]) -> Self {
        var temp = self
        temp.wrapped.yCoordinate = .byteString(ArraySlice(yCoordinate))
        return temp
    }

    func nCoordinate(_ nCoordinate: [UInt8]) -> Self {
        var temp = self
        temp.wrapped.nCoordinate = .byteString(ArraySlice(nCoordinate))
        return temp
    }

    func eCoordiante(_ eCoordinate: [UInt8]) -> Self {
        var temp = self
        temp.wrapped.eCoordinate = .byteString(ArraySlice(eCoordinate))
        return temp
    }
}
