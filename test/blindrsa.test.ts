// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { jest } from '@jest/globals';

import sjcl from '../src/sjcl/index.js';
import { i2osp } from '../src/util.js';
import { BlindRSA, RSABSSA, getSuiteByName } from '../src/index.js';

// Test vectors
// https://www.rfc-editor.org/rfc/rfc9474.html#name-test-vectors
import vectors from './testdata/test_vectors_rfc9474.json';
import { hexNumToB64URL, hexToUint8, uint8ToHex } from './util.js';

type Vector = (typeof vectors)[number];

function paramsFromVector(v: Vector): {
    n: string;
    e: string;
    d: string;
    p: string;
    q: string;
    dp: string;
    dq: string;
    qi: string;
} {
    const n = hexNumToB64URL(v.n);
    const e = hexNumToB64URL(v.e);
    const d = hexNumToB64URL(v.d);
    const p = hexNumToB64URL(v.p);
    const q = hexNumToB64URL(v.q);

    // Calculate CRT values
    const bnD = new sjcl.bn(v.d);
    const bnP = new sjcl.bn(v.p);
    const bnQ = new sjcl.bn(v.q);
    const one = new sjcl.bn(1);
    const dp = hexNumToB64URL(bnD.mod(bnP.sub(one)).toString());
    const dq = hexNumToB64URL(bnD.mod(bnQ.sub(one)).toString());
    const qi = hexNumToB64URL(bnQ.inverseMod(bnP).toString());
    return { n, e, d, p, q, dp, dq, qi };
}

async function keysFromVector(v: Vector, extractable: boolean): Promise<CryptoKeyPair> {
    const params = paramsFromVector(v);
    const { n, e } = params;
    const publicKey = await crypto.subtle.importKey(
        'jwk',
        { kty: 'RSA', ext: true, n, e },
        { name: 'RSA-PSS', hash: 'SHA-384' },
        extractable,
        ['verify'],
    );

    const privateKey = await crypto.subtle.importKey(
        'jwk',
        { kty: 'RSA', ext: true, ...params },
        { name: 'RSA-PSS', hash: 'SHA-384' },
        extractable,
        ['sign'],
    );
    return { privateKey, publicKey };
}

test('Parameters', () => {
    const hash = 'SHA-384';
    const suiteList = [
        { hash, saltLength: 0x30, suite: RSABSSA.SHA384.PSS.Deterministic() },
        { hash, saltLength: 0x30, suite: RSABSSA.SHA384.PSS.Randomized() },
        { hash, saltLength: 0x00, suite: RSABSSA.SHA384.PSSZero.Deterministic() },
        { hash, saltLength: 0x00, suite: RSABSSA.SHA384.PSSZero.Randomized() },
    ];

    for (const v of suiteList) {
        expect(v.suite.params.saltLength).toBe(v.saltLength);
        expect(v.suite.params.hash).toBe(v.hash);
    }
});

describe.each(vectors)('Errors-vec$#', (v: Vector) => {
    test('non-extractable-keys', async () => {
        const { privateKey, publicKey } = await keysFromVector(v, false);
        const msg = crypto.getRandomValues(new Uint8Array(10));
        const blindedMsg = crypto.getRandomValues(new Uint8Array(32));
        const inv = crypto.getRandomValues(new Uint8Array(32));
        const blindedSig = crypto.getRandomValues(new Uint8Array(32));
        const errorMsg = 'key is not extractable';

        const blindRSA = RSABSSA.SHA384.PSS.Randomized();
        await expect(blindRSA.blind(publicKey, msg)).rejects.toThrow(errorMsg);
        await expect(blindRSA.blindSign(privateKey, blindedMsg)).rejects.toThrow(errorMsg);
        await expect(blindRSA.finalize(publicKey, msg, blindedSig, inv)).rejects.toThrow(errorMsg);
    });

    test('wrong-key-type', async () => {
        const { privateKey, publicKey } = await crypto.subtle.generateKey(
            {
                name: 'RSASSA-PKCS1-v1_5', // not RSA-PSS.
                modulusLength: 2048,
                publicExponent: Uint8Array.from([0x01, 0x00, 0x01]),
                hash: 'SHA-256',
            },
            true,
            ['sign', 'verify'],
        );

        const msg = crypto.getRandomValues(new Uint8Array(10));
        const blindedMsg = crypto.getRandomValues(new Uint8Array(32));
        const inv = crypto.getRandomValues(new Uint8Array(32));
        const blindedSig = crypto.getRandomValues(new Uint8Array(32));
        const errorMsg = 'key is not RSA-PSS';

        const blindRSA = RSABSSA.SHA384.PSS.Randomized();
        await expect(blindRSA.blind(publicKey, msg)).rejects.toThrow(errorMsg);
        await expect(blindRSA.blindSign(privateKey, blindedMsg)).rejects.toThrow(errorMsg);
        await expect(blindRSA.finalize(publicKey, msg, blindedSig, inv)).rejects.toThrow(errorMsg);
    });
});

describe.each(vectors)('TestVectors', (v: Vector) => {
    beforeEach(() => {
        const n = new sjcl.bn(v.n);
        const kLen = Math.ceil(n.bitLength() / 8);
        const rInv = new sjcl.bn(v.inv);
        const r = rInv.inverseMod(n);
        const rBytes = i2osp(r, kLen);

        jest.spyOn(crypto, 'getRandomValues')
            .mockReturnValueOnce(hexToUint8(v.msg_prefix)) // mock for msg_prefix
            .mockReturnValueOnce(hexToUint8(v.salt)) // mock for random salt
            .mockReturnValueOnce(rBytes); // mock for random blind
    });

    const params = [undefined, { supportsRSARAW: true }];

    describe.each(params)(`_${v.name}`, (params) => {
        test(
            `supportsRSARAW/${params ? params.supportsRSARAW : false}`,
            async () => {
                const blindRSA = getSuiteByName(BlindRSA, v.name, params);
                expect(blindRSA.toString()).toBe(v.name);

                const msg = hexToUint8(v.msg);
                const inputMsg = blindRSA.prepare(msg);
                expect(uint8ToHex(inputMsg)).toBe(v.input_msg);

                const { publicKey, privateKey } = await keysFromVector(v, true);

                const { blindedMsg, inv } = await blindRSA.blind(publicKey, inputMsg);
                expect(uint8ToHex(blindedMsg)).toBe(v.blinded_msg);
                expect(uint8ToHex(inv)).toBe(v.inv.slice(2));

                const blindedSig = await blindRSA.blindSign(privateKey, blindedMsg);
                expect(uint8ToHex(blindedSig)).toBe(v.blind_sig);

                const signature = await blindRSA.finalize(publicKey, inputMsg, blindedSig, inv);
                expect(uint8ToHex(signature)).toBe(v.sig);

                const isValid = await blindRSA.verify(publicKey, signature, inputMsg);
                expect(isValid).toBe(true);
            },
            20 * 1000,
        );
    });
});
