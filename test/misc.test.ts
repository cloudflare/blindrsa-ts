// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { jest } from '@jest/globals';

import { emsa_pss_encode, is_coprime, random_integer_uniform } from '../src/util.js';
import sjcl from '../src/sjcl/index.js';

// Test vector in file pss_test.go from: https://cs.opensource.google/go/go/+/refs/tags/go1.18.2:src/crypto/rsa/pss_test.go
// Test vector in file pss-int.txt from: ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1-vec.zip
import vector from './testdata/emsa_pss_vectors.json';
import { hexToUint8 } from './util.js';

test('emsa_pss_encode', async () => {
    const hash = 'SHA-1';
    const msg = hexToUint8(vector.msg);
    const salt = hexToUint8(vector.salt);
    const sLen = salt.length;

    jest.spyOn(crypto, 'getRandomValues').mockReturnValueOnce(salt);

    const encoded = await emsa_pss_encode(msg, 1023, { hash, sLen });
    expect(encoded).toStrictEqual(hexToUint8(vector.expected));
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

    jest.spyOn(crypto, 'getRandomValues').mockReturnValue(zeros);
    expect(() => random_integer_uniform(m, mLen)).toThrow(Error);
});
