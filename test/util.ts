// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import sjcl from '../src/sjcl/index.js';

export function hexToUint8(x: string): Uint8Array {
    if (x.startsWith('0x')) {
        x = x.slice(2);
    }
    return new Uint8Array(sjcl.codec.bytes.fromBits(sjcl.codec.hex.toBits(x)));
}

export function uint8ToHex(x: Uint8Array): string {
    return sjcl.codec.hex.fromBits(sjcl.codec.bytes.toBits(Array.from(x)));
}

export function hexNumToB64URL(x: string): string {
    if (x.startsWith('0x')) {
        x = x.slice(2);
    }
    // sjcl.bn.toString drops leading zeros and can yield an odd number of
    // digits, which hex.toBits would then misalign by a nibble.
    if (x.length % 2 !== 0) {
        x = '0' + x;
    }
    return sjcl.codec.base64url.fromBits(sjcl.codec.hex.toBits(x));
}

// The key material of a test vector, as hex strings.
export interface VectorKey {
    n: string;
    e: string;
    d: string;
    p: string;
    q: string;
}

export function publicKeyFromVector(v: Pick<VectorKey, 'n' | 'e'>): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        'jwk',
        { kty: 'RSA', ext: true, n: hexNumToB64URL(v.n), e: hexNumToB64URL(v.e) },
        { name: 'RSA-PSS', hash: 'SHA-384' },
        true,
        ['verify'],
    );
}

export function privateKeyFromVector(v: VectorKey): Promise<CryptoKey> {
    const one = new sjcl.bn(1);
    const d = new sjcl.bn(v.d);
    const p = new sjcl.bn(v.p);
    const q = new sjcl.bn(v.q);
    return crypto.subtle.importKey(
        'jwk',
        {
            kty: 'RSA',
            ext: true,
            n: hexNumToB64URL(v.n),
            e: hexNumToB64URL(v.e),
            d: hexNumToB64URL(v.d),
            p: hexNumToB64URL(v.p),
            q: hexNumToB64URL(v.q),
            // Derived, as the vectors only carry the primes.
            dp: hexNumToB64URL(d.mod(p.sub(one)).toString()),
            dq: hexNumToB64URL(d.mod(q.sub(one)).toString()),
            qi: hexNumToB64URL(q.inverseMod(p).toString()),
        },
        { name: 'RSA-PSS', hash: 'SHA-384' },
        true,
        ['sign'],
    );
}
