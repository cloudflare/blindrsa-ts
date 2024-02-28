// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import sjcl from './sjcl/index.js';
import { random_integer_uniform } from './util.js';

export function generatePrime(bitLength: number, options?: { safe: boolean }): bigint {
    const safe = options?.safe ?? false;
    const kLen = bitLength / 8;
    if (safe) {
        bitLength = bitLength - 1;
    }

    const max = 2n ** BigInt(bitLength);
    let prime: bigint;
    do {
        prime = BigInt(random_integer_uniform(new sjcl.bn(max.toString(16)), kLen).toString());
        if (safe) {
            prime = 2n * prime + 1n;
        }
    } while (!isPrime(prime, 20));
    return prime;
}

function powermod(x: bigint, y: bigint, p: bigint) {
    let res = 1n;

    x = x % p;
    while (y > 0n) {
        if (y & 1n) {
            res = (res * x) % p;
        }

        y = y / 2n;
        x = (x * x) % p;
    }
    return res;
}

function millerTest(n: bigint) {
    let d = n - 1n;
    while (d % 2n == 0n) {
        d /= 2n;
    }
    const r = BigInt(Math.floor(Math.random() * 100_000));
    const y = (r * (n - 2n)) / 100_000n;
    const a = 2n + (y % (n - 4n));

    let x = powermod(a, d, n);

    if (x == 1n || x == n - 1n) {
        return true;
    }

    while (d != n - 1n) {
        x = (x * x) % n;
        d *= 2n;

        if (x == 1n) {
            return false;
        }
        if (x == n - 1n) {
            return true;
        }
    }

    return false;
}

function isPrime(n: bigint, k = 20) {
    if (n <= 1n || n == 4n) {
        return false;
    }
    if (n <= 3n) {
        return true;
    }

    // Iterate given nber of 'k' times
    for (let i = 0; i < k; i++) {
        if (!millerTest(n)) {
            return false;
        }
    }

    return true;
}
