export function generatePrime(bitLength: number, options?: { safe: boolean }): bigint {
    const safe = options?.safe ?? false;
    if (safe) {
        bitLength = bitLength - 1;
    }

    const min = 2n ** BigInt(bitLength - 1);
    const max = 2n ** BigInt(bitLength);
    let prime: bigint;
    do {
        prime = randomBigIntBetween(min, max);
        if (safe) {
            prime = 2n * prime + 1n;
        }
    } while (!isPrime(prime, 20));
    return prime;
}

function randomBigIntBetween(minInclusive: bigint, maxExclusive: bigint) {
    const maxInclusive = maxExclusive - minInclusive - BigInt(1);
    let x = BigInt(1);
    let y = BigInt(0);
    // eslint-disable-next-line no-constant-condition
    while (true) {
        x = x * BigInt(2);
        const randomBit = BigInt(Math.random() < 0.5 ? 1 : 0);
        y = y * BigInt(2) + randomBit;
        if (x > maxInclusive) {
            if (y <= maxInclusive) {
                return y + minInclusive;
            }
            x = x - maxInclusive - BigInt(1);
            y = y - maxInclusive - BigInt(1);
        }
    }
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
