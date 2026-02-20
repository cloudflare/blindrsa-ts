// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import sjcl from './sjcl/index.js';

export function assertNever(name: string, x: unknown): never {
    throw new Error(`unexpected ${name} identifier: ${x}`);
}

interface HashParams {
    name: string;
    hLen: number;
}

function getHashParams(hash: string): HashParams {
    switch (hash) {
        case 'SHA-1':
            return { name: hash, hLen: 20 };
        case 'SHA-256':
            return { name: hash, hLen: 32 };
        case 'SHA-384':
            return { name: hash, hLen: 48 };
        case 'SHA-512':
            return { name: hash, hLen: 64 };
        default:
            assertNever('Hash', hash);
    }
}

export function os2ip(bytes: Uint8Array): sjcl.BigNumber {
    return sjcl.bn.fromBits(sjcl.codec.bytes.toBits(Array.from(bytes)));
}

export function i2osp(num: sjcl.BigNumber, byteLength: number): Uint8Array {
    if (Math.ceil(num.bitLength() / 8) > byteLength) {
        throw new Error(`number does not fit in ${byteLength} bytes`);
    }
    const bytes = new Uint8Array(byteLength);
    const unpadded = new Uint8Array(sjcl.codec.bytes.fromBits(num.toBits(undefined)));
    bytes.set(unpadded, byteLength - unpadded.length);
    return bytes;
}

export function int_to_bytes(num: number, byteLength: number): Uint8Array {
    return i2osp(new sjcl.bn(num), byteLength);
}

export function joinAll(a: Uint8Array[]): Uint8Array<ArrayBuffer> {
    let size = 0;
    for (const ai of a) {
        size += ai.length;
    }
    const ret = new Uint8Array(new ArrayBuffer(size));
    let offset = 0;
    for (const ai of a) {
        ret.set(ai, offset);
        offset += ai.length;
    }
    return ret;
}

export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
    if (a.length !== b.length || a.length === 0) {
        throw new Error(`arrays of different length: ${a.length} - ${b.length}`);
    }
    const ai: IterableIterator<number> = a[Symbol.iterator]();
    const bi: IterableIterator<number> = b[Symbol.iterator]();
    return new Uint8Array(a.length).map(() => ai.next().value ^ bi.next().value);
}

function incCounter(c: Uint8Array): void {
    c[3]++;
    if (c[3] != 0) {
        return;
    }
    c[2]++;
    if (c[2] != 0) {
        return;
    }
    c[1]++;
    if (c[1] != 0) {
        return;
    }
    c[0]++;
    return;
}

type MGFFn = (h: HashParams, seed: Uint8Array, mLen: number) => Promise<Uint8Array>;

// MGF1 (mgfSeed, maskLen)
//
// https://www.rfc-editor.org/rfc/rfc8017#appendix-B.2.1
//
// Options:
// Hash     hash function (hLen denotes the length in octets of
//          the hash function output)
//
// Input:
// mgfSeed  seed from which mask is generated, an octet string
// maskLen  intended length in octets of the mask, at most 2^32 hLen
//
// Output:
// mask     mask, an octet string of length maskLen
//
// Error: "mask too long"
async function mgf1(h: HashParams, seed: Uint8Array, mLen: number): Promise<Uint8Array> {
    // 1.  If maskLen > 2^32 hLen, output "mask too long" and stop.
    const n = Math.ceil(mLen / h.hLen);
    if (n > Math.pow(2, 32)) {
        throw new Error('mask too long');
    }

    // 2.  Let T be the empty octet string.
    let T = new Uint8Array();

    // 3.  For counter from 0 to \ceil (maskLen / hLen) - 1, do the
    //     following:
    const counter = new Uint8Array(4);
    for (let i = 0; i < n; i++) {
        //     A.  Convert counter to an octet string C of length 4 octets (see
        //         Section 4.1):
        //
        //            C = I2OSP (counter, 4) .
        //     B.  Concatenate the hash of the seed mgfSeed and C to the octet
        //         string T:
        //
        //            T = T || Hash(mgfSeed || C) .
        const hash = new Uint8Array(
            await crypto.subtle.digest(h.name, joinAll([seed, counter]).slice().buffer),
        );
        T = joinAll([T, hash]);
        incCounter(counter);
    }

    // 4.  Output the leading maskLen octets of T as the octet string mask.
    return T.subarray(0, mLen);
}

// EMSA-PSS-ENCODE (M, emBits)
//
// https://www.rfc-editor.org/rfc/rfc3447.html#section-9.1.1
//
// Input:
// M        message to be encoded, an octet string
// emBits   maximal bit length of the integer OS2IP (EM) (see Section
//          4.2), at least 8hLen + 8sLen + 9
// MGF      mask generation function
//
// Output:
// EM       encoded message, an octet string of length emLen = \ceil
//          (emBits/8)
//
// Errors:  "encoding error"; "message too long"
export async function emsa_pss_encode(
    msg: Uint8Array,
    emBits: number,
    opts: {
        hash: string;
        sLen: number;
    },
    mgf: MGFFn = mgf1,
): Promise<Uint8Array> {
    const { hash, sLen } = opts;
    const hashParams = getHashParams(hash);
    const { hLen } = hashParams;
    const emLen = Math.ceil(emBits / 8);

    // 1.  If the length of M is greater than the input limitation for the
    //     hash function (2^61 - 1 octets for SHA-1), output "message too
    //     long" and stop.
    //
    // 2.  Let mHash = Hash(M), an octet string of length hLen.
    const mHash = new Uint8Array(await crypto.subtle.digest(hash, msg.slice().buffer));
    // 3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.
    if (emLen < hLen + sLen + 2) {
        throw new Error('encoding error');
    }
    // 4.  Generate a random octet string salt of length sLen; if sLen = 0,
    //     then salt is the empty string.
    const salt = crypto.getRandomValues(new Uint8Array(sLen));
    // 5.  Let
    //       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
    //
    //     M' is an octet string of length 8 + hLen + sLen with eight
    //     initial zero octets.
    //
    const mPrime = joinAll([new Uint8Array(8), mHash, salt]);
    // 6.  Let H = Hash(M'), an octet string of length hLen.
    const h = new Uint8Array(await crypto.subtle.digest(hash, mPrime.slice().buffer));
    // 7.  Generate an octet string PS consisting of emLen - sLen - hLen - 2
    //     zero octets. The length of PS may be 0.
    const ps = new Uint8Array(emLen - sLen - hLen - 2);
    // 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
    //     emLen - hLen - 1.
    const db = joinAll([ps, Uint8Array.of(0x01), salt]);
    // 9.  Let dbMask = MGF(H, emLen - hLen - 1).
    const dbMask = await mgf(hashParams, h, emLen - hLen - 1);
    // 10. Let maskedDB = DB \xor dbMask.
    const maskedDB = xor(db, dbMask);
    // 11.  Set the leftmost 8emLen - emBits bits of the leftmost octet
    //      in maskedDB to zero.
    maskedDB[0] &= 0xff >> (8 * emLen - emBits);
    // 12.  Let EM = maskedDB || H || 0xbc.
    const em = joinAll([maskedDB, h, Uint8Array.of(0xbc)]);

    // 13. Output EM.
    return em;
}

// RSAVP1
// https://www.rfc-editor.org/rfc/rfc3447.html#section-5.2.2
export function rsavp1(
    pkS: { n: sjcl.BigNumber; e: sjcl.BigNumber },
    s: sjcl.BigNumber,
): sjcl.BigNumber {
    //  1. If the signature representative s is not between 0 and n - 1,
    //    output "signature representative out of range" and stop.
    if (!s.greaterEquals(new sjcl.bn(0)) || s.greaterEquals(pkS.n)) {
        throw new Error('signature representative out of range');
    }
    // 2. Let m = s^e mod n.
    const m = s.powermod(pkS.e, pkS.n);
    // 3. Output m.
    return m;
}

// RSASP1
// https://www.rfc-editor.org/rfc/rfc3447.html#section-5.2.1
export function rsasp1(
    skS: { n: sjcl.BigNumber; d: sjcl.BigNumber },
    m: sjcl.BigNumber,
): sjcl.BigNumber {
    // 1. If the message representative m is not between 0 and n - 1,
    //    output "message representative out of range" and stop.
    if (!m.greaterEquals(new sjcl.bn(0)) || m.greaterEquals(skS.n)) {
        throw new Error('signature representative out of range');
    }
    // 2. The signature representative s is computed as follows.
    //
    //    a. If the first form (n, d) of K is used, let s = m^d mod n.
    const s = m.powermod(skS.d, skS.n);
    /* TODO: implement the CRT variant.
    //    b. If the second form (p, q, dP, dQ, qInv) and (r_i, d_i, t_i)
    //       of K is used, proceed as follows:
    //
    //       i.    Let s_1 = m^dP mod p and s_2 = m^dQ mod q.
    //
    //       ii.   If u > 2, let s_i = m^(d_i) mod r_i, i = 3, ..., u.
    //
    //       iii.  Let h = (s_1 - s_2) * qInv mod p.
    //
    //       iv.   Let s = s_2 + q * h.
    //
    //       v.    If u > 2, let R = r_1 and for i = 3 to u do
    //
    //                1. Let R = R * r_(i-1).
    //                2. Let h = (s_i - s) * t_i mod r_i.
    //                3. Let s = s + R * h.
    */
    //   3. Output s.
    return s;
}

export function is_coprime(x: sjcl.BigNumber, n: sjcl.BigNumber): boolean {
    try {
        x.inverseMod(n);
    } catch {
        return false;
    }

    return true;
}

// Generates a random, uniformly distributed integer R between 1 inclusive
// and N exclusive, i.e., 1 <= R < N.
export function random_integer_uniform(n: sjcl.BigNumber, kLen: number): sjcl.BigNumber {
    const MAX_NUM_TRIES = 128;

    for (let i = 0; i < MAX_NUM_TRIES; i++) {
        const r = os2ip(crypto.getRandomValues(new Uint8Array(kLen)));
        if (!(r.greaterEquals(n) || r.equals(0))) {
            return r;
        }
    }

    throw new Error('reached maximum tries for random integer generation');
}

// implement inverseMod for sjcl.bn where p is even
// taken from Wikipedia pseudocode for the extended euclidian algorithm
// ref https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers
export function inverseMod(x: sjcl.BigNumber, p: sjcl.BigNumber): sjcl.BigNumber {
    if (!(p.getLimb(0) & 1)) {
        if (!(x.getLimb(0) & 1)) {
            throw new Error('inverseMod: The given number is not invertible.');
        }

        let [old_r, r] = [BigInt(x.toString()), BigInt(p.toString())];
        let [old_s, s] = [BigInt(1), BigInt(0)];

        while (r !== 0n) {
            const quotient = old_r / r;
            [old_r, r] = [r, old_r - quotient * r];
            [old_s, s] = [s, old_s - quotient * s];
        }

        if (old_r > 1n) {
            throw new Error('inverseMod: The given number is not invertible.');
        }
        if (old_s < 0n) {
            old_s += BigInt(p.toString());
        }
        return new sjcl.bn(old_s.toString(16));
    }
    return x.inverseMod(p);
}

export const NATIVE_SUPPORT_NAME = 'RSA-RAW';

export async function rsaRawBlingSign(
    privateKey: CryptoKey,
    blindMsg: Uint8Array,
): Promise<Uint8Array> {
    if (privateKey.algorithm.name !== NATIVE_SUPPORT_NAME) {
        privateKey = await crypto.subtle.importKey(
            'pkcs8',
            await crypto.subtle.exportKey('pkcs8', privateKey),
            { ...privateKey.algorithm, name: NATIVE_SUPPORT_NAME },
            privateKey.extractable,
            privateKey.usages,
        );
    }
    const signature = await crypto.subtle.sign(
        { name: privateKey.algorithm.name },
        privateKey,
        blindMsg.slice().buffer,
    );
    return new Uint8Array(signature);
}

export type BigPublicKey = { e: sjcl.BigNumber; n: sjcl.BigNumber };

export type BigSecretKey = {
    d: sjcl.BigNumber;
    n: sjcl.BigNumber;
    p: sjcl.BigNumber;
    q: sjcl.BigNumber;
};

export type BigKeyPair = { publicKey: BigPublicKey; secretKey: BigSecretKey };

export function prepare_sjcl_random_generator() {
    // It requires to seed the internal random number generator.
    const source = 'crypto.getRandomValues';
    while (!sjcl.random.isReady(undefined)) {
        sjcl.random.addEntropy(Array.from(crypto.getRandomValues(new Uint32Array(4))), 128, source);
    }
}
