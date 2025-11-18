// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import sjcl from './sjcl/index.js';

const SJCL_PARANOIA = 6;

// Miller-Rabin probabilistic primality test.
// Algorithm 4.24 of Handbook Applied Cryptography.
// https://cacr.uwaterloo.ca/hac/about/chap4.pdf
function millerRabinTest(n: sjcl.BigNumber, SEC_PARAM: number): boolean {
    if (n.equals(1)) {
        return false;
    }
    if (n.equals(2) || n.equals(3)) {
        return true;
    }
    if ((n.getLimb(0) & 0x1) === 0) {
        return false;
    }

    const nMinusOne = new sjcl.bn(n).sub(1).normalize();
    let r = new sjcl.bn(nMinusOne);
    let s = 0;

    while ((r.getLimb(0) & 0x1) === 0) {
        r = r.halveM();
        s++;
    }

    for (let i = 0; i < SEC_PARAM; i++) {
        const a = sjcl.bn.random(nMinusOne, SJCL_PARANOIA);
        let y = a.powermod(r, n);
        if (!y.equals(1) && !y.equals(nMinusOne)) {
            let j = 1;
            while (j < s && !y.equals(nMinusOne)) {
                y = y.mulmod(y, n);
                if (y.equals(1)) {
                    return false;
                }
                j++;
            }
            if (!y.equals(nMinusOne)) {
                return false;
            }
        }
    }

    return true;
}

export function isPrime(number: bigint, SEC_PARAM = 20): boolean {
    return millerRabinTest(new sjcl.bn(number.toString(16)), SEC_PARAM);
}

export function isSafePrime(number: bigint, SEC_PARAM = 20): boolean {
    const n = new sjcl.bn(number.toString(16));
    const nDivTwo = new sjcl.bn(n).halveM().normalize();
    return millerRabinTest(n, SEC_PARAM) && millerRabinTest(nDivTwo, SEC_PARAM);
}

function generatePrimeBn(bitLength: number, NUM_TRIES_PRIMALITY: number): sjcl.BigNumber {
    // NUM_TRIES is O(k*b^4) in the worst case,
    // where:
    //   k is the Miller-Rabin primality test parameter,
    //   b is the bit length requested.
    const MAX_NUM_TRIES = NUM_TRIES_PRIMALITY * bitLength ** 4;

    // 2^(b-1)
    const twoToN1 = new sjcl.bn(1);
    for (let i = 0; i < bitLength - 1; i++) {
        twoToN1.doubleM();
    }

    let prime: sjcl.BigNumber;
    let i = 0;

    do {
        prime = sjcl.bn.random(twoToN1, SJCL_PARANOIA);
        prime.addM(twoToN1);
        if ((prime.getLimb(0) & 0x1) == 0) {
            prime = prime.addM(1).normalize();
        }
        i++;
    } while (!millerRabinTest(prime, NUM_TRIES_PRIMALITY) && i < MAX_NUM_TRIES);

    if (i === MAX_NUM_TRIES) {
        throw new Error(`generatePrime reached MAX_NUM_TRIES=${MAX_NUM_TRIES}`);
    }

    return prime;
}

// Brute-force prime search using Miller-Rabin test oracle.
// https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Generation_of_probable_primes
export function generatePrime(bitLength: number, NUM_TRIES_PRIMALITY = 20): bigint {
    return BigInt(generatePrimeBn(bitLength, NUM_TRIES_PRIMALITY).toString());
}

function generateSafePrimeBn(bitLength: number, NUM_TRIES_PRIMALITY: number): sjcl.BigNumber {
    const MAX_NUM_TRIES = bitLength ** 2;
    const ONE = new sjcl.bn(1);
    let prime: sjcl.BigNumber;
    let i = 0;

    do {
        const q = generatePrimeBn(bitLength - 1, NUM_TRIES_PRIMALITY);
        prime = q.doubleM().addM(ONE).normalize();
        i++;
    } while (!millerRabinTest(prime, NUM_TRIES_PRIMALITY) && i < MAX_NUM_TRIES);

    if (i === MAX_NUM_TRIES) {
        throw new Error(`generateSafePrime reached MAX_NUM_TRIES=${MAX_NUM_TRIES}`);
    }

    return prime;
}

// Brute-force safe prime search using Miller-Rabin test oracle.
// Returns p=2*q+1 such that both p and q are prime numbers.
export function generateSafePrime(bitLength: number, NUM_TRIES_PRIMALITY = 20): bigint {
    return BigInt(generateSafePrimeBn(bitLength, NUM_TRIES_PRIMALITY).toString());
}
