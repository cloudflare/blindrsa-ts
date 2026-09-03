// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { expect, test, vi } from 'vitest';

import {
    emsa_pss_encode,
    is_coprime,
    random_integer_uniform,
    rsasp1,
    rsavp1,
} from '../src/util.js';
import sjcl from '../src/sjcl/index.js';

// Test vector in file pss_test.go from: https://cs.opensource.google/go/go/+/refs/tags/go1.18.2:src/crypto/rsa/pss_test.go
// Test vector in file pss-int.txt from: ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1-vec.zip
import vector from './testdata/emsa_pss_vectors.json' with { type: 'json' };
import { hexToUint8 } from './util.js';

test('emsa_pss_encode', async () => {
    const hash = 'SHA-1';
    const msg = hexToUint8(vector.msg);
    const salt = hexToUint8(vector.salt);
    const sLen = salt.length;

    vi.spyOn(crypto, 'getRandomValues').mockReturnValueOnce(salt);

    const encoded = await emsa_pss_encode(msg, 1023, { hash, sLen });
    expect(encoded).toStrictEqual(hexToUint8(vector.expected));
});

// A representative of zero is in range for both primitives, and an attacker
// can supply one: a blinded message of zero reaches rsasp1 in blindSign, and a
// signature of zero reaches rsavp1 when verifying. sjcl's own powermod throws
// a TypeError on a zero base, so these guard that the primitives answer
// instead of crashing.
test('rsavp1/accepts a representative of zero', () => {
    const n = new sjcl.bn('0xd6930820f71fe517bf3259d14d40209b02a5c0d3d61991c731dd7da39f8d6983');
    const e = new sjcl.bn(0x10001);
    expect(rsavp1({ n, e }, new sjcl.bn(0)).equals(0)).toBe(true);
    expect(() => new sjcl.bn(0).powermod(e, n)).toThrow(TypeError);
});

test('rsasp1/accepts a representative of zero', () => {
    const n = new sjcl.bn('0xd6930820f71fe517bf3259d14d40209b02a5c0d3d61991c731dd7da39f8d6983');
    const d = new sjcl.bn('0x2f0b1c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f1');
    expect(rsasp1({ n, d }, new sjcl.bn(0)).equals(0)).toBe(true);
});

test('is_coprime', () => {
    const m = new sjcl.bn(3 * 5);
    expect(is_coprime(new sjcl.bn(1), m)).toBe(true);
    expect(is_coprime(new sjcl.bn(2), m)).toBe(true);
    expect(is_coprime(new sjcl.bn(3), m)).toBe(false);
    expect(is_coprime(new sjcl.bn(5), m)).toBe(false);
});

test('random_integer_uniform', () => {
    const m = new sjcl.bn(256);
    const mLen = 2;
    const zeros = new Uint8Array(mLen);

    vi.spyOn(crypto, 'getRandomValues').mockReturnValue(zeros);
    expect(() => random_integer_uniform(m, mLen)).toThrow(Error);
});
