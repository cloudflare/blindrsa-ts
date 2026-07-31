// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import sjcl from '../src/sjcl/index.js';
import { beforeAll, describe, expect, test } from 'vitest';

import { i2osp, joinAll } from '../src/util.js';
import { PartiallyBlindRSA, getSuiteByName } from '../src/index.js';
import type { PartiallyBlindRSABackend, PartiallyBlindRSAContext } from '../src/index.js';
import { wasmBackend } from '../src/wasm/node.js';

import { hexToUint8, privateKeyFromVector, publicKeyFromVector, uint8ToHex } from './util.js';
// https://datatracker.ietf.org/doc/html/draft-amjad-cfrg-partially-blind-rsa-02#name-test-vectors
import vectors from './testdata/test_vectors_partially_blind_rsa_draft_2.json' with { type: 'json' };

type Vector = (typeof vectors)[number];

let backend: PartiallyBlindRSABackend;

beforeAll(async () => {
    backend = await wasmBackend();
}, 60_000);

test('wasmBackend/is reused across calls', async () => {
    await expect(wasmBackend()).resolves.toBe(backend);
});

// A host without entropy has to produce an ordinary error. The generator the
// crate offers by default panics, which under panic = "abort" is a WebAssembly
// trap: opaque to the caller, and it abandons the arguments of the call it
// aborts in linear memory, so a caller retrying in a loop grows it without
// bound.
test('blind/reports missing entropy as an error, and recovers', async () => {
    const v = vectors[0];
    const ctx = {
        n: hexToUint8(v.n),
        e: hexToUint8(v.e),
        info: hexToUint8(v.info),
        hash: 'SHA-384',
        saltLength: 48,
    };
    const message = hexToUint8(v.msg);
    const realCrypto = globalThis.crypto;
    const setCrypto = (value: Crypto | undefined): void => {
        Object.defineProperty(globalThis, 'crypto', { value, configurable: true, writable: true });
    };

    setCrypto(undefined);
    try {
        await expect(backend.blind(ctx, message)).rejects.toThrow(/internal error/i);
    } finally {
        setCrypto(realCrypto);
    }
    // Entropy is drawn per operation, so the next one succeeds.
    await expect(backend.blind(ctx, message)).resolves.toBeDefined();
}, 60_000);

describe.each(vectors)('Wasm_%#', (v: Vector) => {
    const msg = hexToUint8(v.msg);
    const info = hexToUint8(v.info);
    const sig = hexToUint8(v.sig);
    // Every draft-02 vector uses deterministic preparation, so the prepared
    // message carries an empty prefix.
    const inputMsg = joinAll([hexToUint8(v.msg_prefix), msg]);
    const kLen = Math.ceil(new sjcl.bn(v.n).bitLength() / 8);
    // inv is the blinding inverse the vector's r unblinds with.
    const inv = i2osp(new sjcl.bn(v.r).inverseMod(new sjcl.bn(v.n)), kLen);

    function suite(): PartiallyBlindRSA {
        return getSuiteByName(PartiallyBlindRSA, v.name, { supportsRSARAW: false, backend });
    }

    function withByteXored(x: Uint8Array, index: number, mask: number): Uint8Array {
        const original = x.at(index);
        if (original === undefined) {
            throw new Error(`index ${index} out of bounds`);
        }
        const mutated = x.slice();
        mutated.set([original ^ mask], index);
        return mutated;
    }

    // Two vectors carry an empty message or empty metadata, so a differing
    // input has to be produced by extending rather than flipping.
    function madeDifferent(x: Uint8Array): Uint8Array {
        return x.length === 0 ? Uint8Array.of(0x00) : withByteXored(x, 0, 0x01);
    }

    test('verify/accepts the test vector signature', async () => {
        const publicKey = await publicKeyFromVector(v);
        await expect(suite().verify(publicKey, sig, inputMsg, info)).resolves.toBe(true);
    });

    test('finalize/reproduces the test vector signature', async () => {
        const publicKey = await publicKeyFromVector(v);
        const signature = await suite().finalize(
            publicKey,
            inputMsg,
            info,
            hexToUint8(v.blind_sig),
            inv,
        );
        expect(uint8ToHex(signature)).toBe(v.sig);
    });

    test.each([
        ['a tampered signature', () => withByteXored(sig, 0, 0x01)],
        ['a truncated signature', () => sig.subarray(0, sig.length - 1)],
        ['an over-long signature', () => joinAll([sig, Uint8Array.of(0x00)])],
        ['a zero signature', () => new Uint8Array(sig.length)],
        // s must lie in [0, n-1]; n itself is out of range.
        ['an out-of-range signature', () => i2osp(new sjcl.bn(v.n), sig.length)],
    ])('verify/rejects %s', async (_, makeSignature) => {
        const publicKey = await publicKeyFromVector(v);
        await expect(suite().verify(publicKey, makeSignature(), inputMsg, info)).resolves.toBe(
            false,
        );
    });

    test('verify/rejects another message', async () => {
        const publicKey = await publicKeyFromVector(v);
        await expect(suite().verify(publicKey, sig, madeDifferent(inputMsg), info)).resolves.toBe(
            false,
        );
    });

    test('verify/rejects other metadata', async () => {
        const publicKey = await publicKeyFromVector(v);
        await expect(suite().verify(publicKey, sig, inputMsg, madeDifferent(info))).resolves.toBe(
            false,
        );
    });

    test('finalize/rejects an invalid signature', async () => {
        const publicKey = await publicKeyFromVector(v);
        // A well-formed but unrelated inverse unblinds to a bad signature.
        const wrongInv = i2osp(new sjcl.bn(2), kLen);
        await expect(
            suite().finalize(publicKey, inputMsg, info, hexToUint8(v.blind_sig), wrongInv),
        ).rejects.toThrow();
    });

    test.each([
        ['a short inverse', () => ({ blindSig: hexToUint8(v.blind_sig), inv: inv.subarray(1) })],
        ['a short blind signature', () => ({ blindSig: hexToUint8(v.blind_sig).subarray(1), inv })],
    ])('finalize/rejects %s like the default client', async (_, makeInput) => {
        const publicKey = await publicKeyFromVector(v);
        const { blindSig, inv: badInv } = makeInput();
        const message = 'unexpected input size';

        await expect(suite().finalize(publicKey, inputMsg, info, blindSig, badInv)).rejects.toThrow(
            message,
        );
        await expect(
            getSuiteByName(PartiallyBlindRSA, v.name).finalize(
                publicKey,
                inputMsg,
                info,
                blindSig,
                badInv,
            ),
        ).rejects.toThrow(message);
    });

    // The signature the wasm client produces has to verify under the default
    // WebCrypto path, and vice versa, or the two implementations have drifted.
    //
    // The vectors only cover PSS-Deterministic, but a round trip needs no
    // vector data beyond the key, so every suite is exercised here: this is
    // the only coverage of the PSSZERO salt mode and of randomized
    // preparation against the backend.
    test.each([
        'RSAPBSSA-SHA384-PSS-Deterministic',
        'RSAPBSSA-SHA384-PSS-Randomized',
        'RSAPBSSA-SHA384-PSSZERO-Deterministic',
        'RSAPBSSA-SHA384-PSSZERO-Randomized',
    ])(
        'blind/round-trips against the default issuer and verifier: %s',
        async (name) => {
            const publicKey = await publicKeyFromVector(v);
            const privateKey = await privateKeyFromVector(v);
            const wasmSuite = getSuiteByName(PartiallyBlindRSA, name, {
                supportsRSARAW: false,
                backend,
            });
            const defaultSuite = getSuiteByName(PartiallyBlindRSA, name);

            const prepared = wasmSuite.prepare(msg);
            const { blindedMsg, inv: blindInv } = await wasmSuite.blind(publicKey, prepared, info);
            expect(blindedMsg).toHaveLength(kLen);
            expect(blindInv).toHaveLength(kLen);
            // The blinded message goes to the issuer while the inverse stays
            // secret, so they must not share a buffer.
            expect(blindedMsg.buffer).not.toBe(blindInv.buffer);
            expect(blindedMsg.buffer.byteLength).toBe(kLen);

            const blindSig = await defaultSuite.blindSign(privateKey, blindedMsg, info);
            const signature = await wasmSuite.finalize(
                publicKey,
                prepared,
                info,
                blindSig,
                blindInv,
            );

            await expect(wasmSuite.verify(publicKey, signature, prepared, info)).resolves.toBe(
                true,
            );
            await expect(defaultSuite.verify(publicKey, signature, prepared, info)).resolves.toBe(
                true,
            );
        },
        60_000,
    );

    test.each([
        ['a zero modulus', () => Uint8Array.of(0)],
        ['a modulus below 1024 bits', () => hexToUint8(v.n).subarray(0, 64)],
    ])('verify/reports %s as an error, not a bad signature', async (_, makeModulus) => {
        // Straight to the backend: PartiallyBlindRSA only accepts a CryptoKey,
        // which cannot carry a modulus this malformed.
        const ctx = {
            n: makeModulus(),
            e: hexToUint8(v.e),
            info,
            hash: 'SHA-384',
            saltLength: 48,
        };
        await expect(backend.verify(ctx, inputMsg, sig)).rejects.toThrow();
    });

    // The crate derives the per-metadata exponent with the modulus encoded to
    // its crypto-bigint precision, which rounds up to whole 64-bit limbs. Where
    // that adds padding, the derived exponent is not the one the draft
    // specifies, so no other implementation agrees: signatures verified here
    // would be rejected elsewhere, and valid ones rejected here. A modulus of
    // 2056 bits is such a size, and 2048 is not. The backend has to refuse it,
    // not answer that the signature is bad.
    test.each([
        ['verify', (ctx: PartiallyBlindRSAContext) => backend.verify(ctx, inputMsg, sig)],
        ['blind', (ctx: PartiallyBlindRSAContext) => backend.blind(ctx, inputMsg)],
        [
            'finalize',
            (ctx: PartiallyBlindRSAContext) =>
                backend.finalize(ctx, inputMsg, hexToUint8(v.blind_sig), inv),
        ],
    ])(
        '%s/reports a modulus that is not a multiple of 64 bits as an error',
        async (_, operation) => {
            const ctx = {
                // 257 bytes: the vector modulus with a byte prepended, so
                // no longer a whole number of 64-bit limbs.
                n: joinAll([Uint8Array.of(1), hexToUint8(v.n)]),
                e: hexToUint8(v.e),
                info,
                hash: 'SHA-384',
                saltLength: 48,
            };
            await expect(operation(ctx)).rejects.toThrow();
        },
    );

    test('finalize/accepts a blinding produced by the default client', async () => {
        const publicKey = await publicKeyFromVector(v);
        const privateKey = await privateKeyFromVector(v);
        const wasmSuite = suite();
        const defaultSuite = getSuiteByName(PartiallyBlindRSA, v.name);

        const prepared = defaultSuite.prepare(msg);
        const { blindedMsg, inv: blindInv } = await defaultSuite.blind(publicKey, prepared, info);
        const blindSig = await defaultSuite.blindSign(privateKey, blindedMsg, info);

        const signature = await wasmSuite.finalize(publicKey, prepared, info, blindSig, blindInv);
        await expect(wasmSuite.verify(publicKey, signature, prepared, info)).resolves.toBe(true);
    }, 60_000);
});
