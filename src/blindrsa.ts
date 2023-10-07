// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import sjcl from './sjcl/index.js';

import {
    assertNever,
    emsa_pss_encode,
    i2osp,
    is_coprime,
    joinAll,
    os2ip,
    random_integer_uniform,
    rsasp1,
    rsavp1,
} from './util.js';

export enum PrepareType {
    Deterministic = 0,
    Randomized = 32,
}

export type BlindOutput = { blindedMsg: Uint8Array; inv: Uint8Array };

export interface BlindRSAParams {
    name: string;
    hash: string;
    saltLength: number;
    prepareType: PrepareType;
}

export class BlindRSA {
    private static readonly NAME = 'RSA-PSS';

    constructor(public readonly params: BlindRSAParams) {
        switch (params.prepareType) {
            case PrepareType.Deterministic:
            case PrepareType.Randomized:
                return;
            default:
                assertNever('PrepareType', params.prepareType);
        }
    }

    toString(): string {
        return `RSABSSA-${this.params.hash.replace('-', '')}-PSS${
            this.params.saltLength === 0 ? 'ZERO' : ''
        }-${PrepareType[this.params.prepareType]}`;
    }

    prepare(msg: Uint8Array): Uint8Array {
        const msg_prefix_len = this.params.prepareType;
        const msg_prefix = crypto.getRandomValues(new Uint8Array(msg_prefix_len));
        return joinAll([msg_prefix, msg]);
    }

    // Returns the parameters of the input key: the JSONWebKey data, the length
    // in bits and in bytes of the modulus, and the hash function used.
    private async extractKeyParams(
        key: CryptoKey,
        type: 'public' | 'private',
    ): Promise<{
        jwkKey: JsonWebKey;
        modulusLengthBits: number;
        modulusLengthBytes: number;
        hash: string;
    }> {
        if (key.type !== type || key.algorithm.name !== BlindRSA.NAME) {
            throw new Error(`key is not ${BlindRSA.NAME}`);
        }
        if (!key.extractable) {
            throw new Error('key is not extractable');
        }

        const { modulusLength: modulusLengthBits, hash: hashFn } =
            key.algorithm as RsaHashedKeyGenParams;
        const modulusLengthBytes = Math.ceil(modulusLengthBits / 8);
        const hash = (hashFn as Algorithm).name;
        if (hash.toLowerCase() !== this.params.hash.toLowerCase()) {
            throw new Error(`hash is not ${this.params.hash}`);
        }
        const jwkKey = await crypto.subtle.exportKey('jwk', key);

        return { jwkKey, modulusLengthBits, modulusLengthBytes, hash };
    }

    async blind(publicKey: CryptoKey, msg: Uint8Array): Promise<BlindOutput> {
        const {
            jwkKey,
            modulusLengthBits: modulusLength,
            modulusLengthBytes: kLen,
            hash,
        } = await this.extractKeyParams(publicKey, 'public');
        if (!jwkKey.n || !jwkKey.e) {
            throw new Error('key has invalid parameters');
        }
        const n = sjcl.bn.fromBits(sjcl.codec.base64url.toBits(jwkKey.n));
        const e = sjcl.bn.fromBits(sjcl.codec.base64url.toBits(jwkKey.e));
        const pk = { e, n };

        // 1. encoded_msg = EMSA-PSS-ENCODE(msg, bit_len(n))
        //    with Hash, MGF, and salt_len as defined in the parameters
        // 2. If EMSA-PSS-ENCODE raises an error, raise the error and stop
        const opts = { sLen: this.params.saltLength, hash };
        const encoded_msg = await emsa_pss_encode(msg, modulusLength - 1, opts);

        // 3. m = bytes_to_int(encoded_msg)
        const m = os2ip(encoded_msg);

        // 4. c = is_coprime(m, n)
        // 5. If c is false, raise an "invalid input" error
        //    and stop
        const c = is_coprime(m, n);
        if (c === false) {
            throw new Error('invalid input');
        }

        // 6. r = random_integer_uniform(1, n)
        const r = random_integer_uniform(n, kLen);

        // 7. inv = inverse_mod(r, n)
        // 8. If inverse_mod fails, raise a "blinding error" error
        //    and stop
        let inv: Uint8Array;
        try {
            inv = i2osp(r.inverseMod(n), kLen);
        } catch (e) {
            throw new Error(`blinding error: ${(e as Error).toString()}`);
        }

        // 9. x = RSAVP1(pk, r)
        const x = rsavp1(pk, r);

        // 10. z = m * x mod n
        const z = m.mulmod(x, n);

        // 11. blinded_msg = int_to_bytes(z, modulus_len)
        const blindedMsg = i2osp(z, kLen);

        // 12. output blinded_msg, inv
        return { blindedMsg, inv };
    }

    async blindSign(privateKey: CryptoKey, blindMsg: Uint8Array): Promise<Uint8Array> {
        const { jwkKey, modulusLengthBytes: kLen } = await this.extractKeyParams(
            privateKey,
            'private',
        );
        if (!jwkKey.n || !jwkKey.d) {
            throw new Error('key has invalid parameters');
        }
        const n = sjcl.bn.fromBits(sjcl.codec.base64url.toBits(jwkKey.n));
        const d = sjcl.bn.fromBits(sjcl.codec.base64url.toBits(jwkKey.d));
        const e = sjcl.bn.fromBits(sjcl.codec.base64url.toBits(jwkKey.e));
        const sk = { n, d };
        const pk = { n, e };

        // 1. m = bytes_to_int(blinded_msg)
        const m = os2ip(blindMsg);

        // 2. s = RSASP1(sk, m)
        const s = rsasp1(sk, m);

        // 3. m' = RSAVP1(pk, s)
        const mp = rsavp1(pk, s);

        // 4. If m != m', raise "signing failure" and stop
        if (m.equals(mp) === false) {
            throw new Error('signing failure');
        }

        // 5. blind_sig = int_to_bytes(s, kLen)
        // 6. output blind_sig
        return i2osp(s, kLen);
    }

    async finalize(
        publicKey: CryptoKey,
        msg: Uint8Array,
        blindSig: Uint8Array,
        inv: Uint8Array,
    ): Promise<Uint8Array> {
        const { jwkKey, modulusLengthBytes: kLen } = await this.extractKeyParams(
            publicKey,
            'public',
        );
        if (!jwkKey.n) {
            throw new Error('key has invalid parameters');
        }
        const n = sjcl.bn.fromBits(sjcl.codec.base64url.toBits(jwkKey.n));

        // 0. If len(inv) != kLen, raise "unexpected input size" and stop
        //    rInv = bytes_to_int(inv)
        if (inv.length != kLen) {
            throw new Error('unexpected input size');
        }
        const rInv = os2ip(inv);

        // 1. If len(blind_sig) != kLen, raise "unexpected input size" and stop
        if (blindSig.length != kLen) {
            throw new Error('unexpected input size');
        }

        // 2. z = bytes_to_int(blind_sig)
        const z = os2ip(blindSig);

        // 3. s = z * inv mod n
        const s = z.mulmod(rInv, n);

        // 4. sig = int_to_bytes(s, kLen)
        const sig = i2osp(s, kLen);

        // 5. result = RSASSA-PSS-VERIFY(pk, msg, sig)
        // 6. If result = "valid signature", output sig, else
        //    raise "invalid signature" and stop
        const algorithm = { name: BlindRSA.NAME, saltLength: this.params.saltLength };
        if (!(await crypto.subtle.verify(algorithm, publicKey, sig, msg))) {
            throw new Error('invalid signature');
        }

        return sig;
    }

    static generateKey(
        algorithm: Pick<RsaHashedKeyGenParams, 'modulusLength' | 'publicExponent' | 'hash'>,
    ): Promise<CryptoKeyPair> {
        return crypto.subtle.generateKey({ ...algorithm, name: 'RSA-PSS' }, true, [
            'sign',
            'verify',
        ]);
    }

    generateKey(
        algorithm: Pick<RsaHashedKeyGenParams, 'modulusLength' | 'publicExponent'>,
    ): Promise<CryptoKeyPair> {
        return BlindRSA.generateKey({ ...algorithm, hash: this.params.hash });
    }

    verify(publicKey: CryptoKey, signature: Uint8Array, message: Uint8Array): Promise<boolean> {
        return crypto.subtle.verify(
            { name: BlindRSA.NAME, saltLength: this.params.saltLength },
            publicKey,
            signature,
            message,
        );
    }
}
