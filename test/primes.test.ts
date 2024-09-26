// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { jest } from '@jest/globals';

import sjcl from '../src/sjcl/index.js';

import { generatePrime, generateSafePrime, isPrime, isSafePrime } from '../src/prime.js';

const PRIME = [
    '0x2',
    '0x3',
    '0xca2be15d71',
    '0x6c08814960c6d55a2b',
    '0x85b56022215b6188702e214cd1',
    '0xf2abae929d12675e3bf2acb18467e9ef41',
    '0xdafaadccadb9018d2d9d75133660e863a8dc4306d1',
    '0xe6d3b0e9b741abe5a9e7e9413b2dbab3646c392ff4d1addbfb',
    '0xd42f80dc5e9fe12c7c3c4cf837cd4d313f5aec5773a1968cdd75510a63',
    '0xfc96843c719d86de45a47df2f33255e6bd202de56994dc25569c746d9fec402da7',
    '0x730b2b9f40c0c0ec660534bf63ba74857abf37eb7bf68884abdc6c5966345f6e67936e9b9f',
    '0xc9ca6213c87a6bd60dfcd2b95967ed779567dea1687a35a4baf7275c23943b3dc70644214df64f33e3',
    '0x1e2d8976dad6f0c35699184226fc7a41e622e064e02fb7f98f49d1d8eb2bf0454296684b5839d69636384aed6b',
    '0xfe6d84debd1ae4edf9430e9dba91ba5a2ee5b34f42deab27a4fbf73a4573d3eb184f34b5f0bbc73d9b6015058db1fae21f',
    '0x4417733bb3da0479459034f0bdfa3ccc9c62d964da9b41b2e467f1537a8a7db640fa7d32990156de8099f494684da5885658bfa137',
    '0x1ad48868e626efba780ba019fb348ba0b203b26a77cf4269d42c5eeadb1cde4a2a3468f6ca6f8c8b39494b21be672e7fa28d5944698453f6b7',
    '0x4134536d5dbc6a47ae3840c0e43ff604075577d380fe8ce5395bd59d717f5675be4f20be55b0bae6abb6dfe17ac899aeb18559f9c6138e535950f84d47',
];

// Carmichael numbers (OEIS A074379)
const A074379 = [41041, 62745, 63973, 75361, 101101, 126217, 172081, 188461, 278545, 340561];

const COMPOSITE = [
    '0x1',
    '0x8acbc1f935',
    '0x8de26a5d80cb0cd651',
    '0x93e460207596f2f32eb96169e3',
    '0xc4129f113142321409fd48796bda12affd',
    '0x8d953a42acd191bca23ae256e34041b8389a5ad628',
    '0xa06384bea6d2c95182feb2adbe2ca0cbe48364697dce3243cf',
    '0xe4d09886b3c5af4ac96eae0ea17b04af332a40a683502c3d2aff764556',
    '0x9b6625fd3875555d4bec60d65c5d8ee39049ce54e1b1f0a6845626d4a948326f44',
    '0xfba2ee8b8c71909ac84597942cc2ea73bb6edac6363efa3eeecc224eec2773ac2e013a3199',
    '0xf03055a851d997f857b43140bf4008cceacf549e0da684754eac96cddc1c2e2027d79ff1d28175a739',
    '0xfc85512cc2cbc7e78c3960e5e51da6201dcd96d837a223097494773afdb900cd1656a04a945ee4db7d9d5e7fe4',
    '0xf11c8d6cade87593ac3675211a0c09fa3b2646fc593bd4875b199d117cfa1c883fa2466c58c0f08a3d3ee1a562db4e30f1',
    '0xd020dca4e2acfc6db31ce8e8d0f07d6b021e4058f848ec71fcebcb335dbb0e7abb148fcde2653d17b8c19068bf425b2718fbbfdb40',
    '0xbeed6e4ea3c72d14021b2da3031effb337ef9ede53e65222121b04ed6255b86a3af4a905b3a53389dc6d1b9bf1a04bb603f51209f1901b1007',
    '0xdebe8c3befa13928244d75fa8217f82a231d1cb8b4cb8842c58f2edb20ca3dce7ce09683a6ac702760ef5026a6562ad6e2e8d0262da655a3beb667eaaa',
];

const SAFE_PRIMES = [
    '0xf250bc4c07',
    '0xac2bb90f40c83baa4b',
    '0x91377ec5a6dcf59679a4a7049f',
    '0x5a675b388f8d16c5fe62b205f50760de5b',
    '0xc9c9c2ef87194271ef8f559f61d9397f6dbe04b4cb',
    '0x9f668aebc2e03e31cd4e59c5e9e2222470c4e6b7a3c1e99043',
    '0x9f62917a38e8136a8d942aa6854637800713ad3bd0b58d971910c5c233',
];

beforeEach(() => {
    // It requires to seed the internal random number generator.
    while (!sjcl.random.isReady(undefined)) {
        sjcl.random.addEntropy(
            Array.from(crypto.getRandomValues(new Uint32Array(4))),
            128,
            'undefined',
        );
    }
});

test.each(PRIME)('isPrime/%#', (p) => {
    expect(isPrime(new sjcl.bn(p))).toBe(true);
});

test.each(A074379)('notPrimeCarmichael/%#', (p) => {
    expect(isPrime(new sjcl.bn(p))).toBe(false);
});

test.each(COMPOSITE)('notPrime/%#', (p) => {
    expect(isPrime(new sjcl.bn(p))).toBe(false);
});

test.each(SAFE_PRIMES)('isSafePrime/%#', (p) => {
    expect(isSafePrime(new sjcl.bn(p))).toBe(true);
});

test.each([128, 256, 512, 1024])('generatePrime/%p', (bitLength) => {
    const p = generatePrime(bitLength);

    expect(p.bitLength()).toBeGreaterThanOrEqual(bitLength);
    expect(isPrime(p)).toBe(true);
});

test.each([128, 256])('generateSafePrime/%p', (bitLength) => {
    const p = generateSafePrime(bitLength);

    expect(p.bitLength()).toBeGreaterThanOrEqual(bitLength);
    expect(isSafePrime(p)).toBe(true);
});

describe('max_num_iterations', () => {
    test('generatePrime', () => {
        // it always returns 1, which is not a prime
        jest.spyOn(sjcl.bn, 'random').mockReturnValue(new sjcl.bn(1));

        expect(() => {
            generatePrime(8);
        }).toThrow(/MAX_NUM_TRIES/);
    });
});
