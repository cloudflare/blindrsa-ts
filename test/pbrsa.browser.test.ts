// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

// Runs the partially blind RSA client in a real browser, which is the
// environment the WebAssembly backend exists for: WebCrypto there rejects the
// metadata-derived public exponent, so `finalize` and `verify` cannot use it.
//
// Executed by vitest.browser.config.ts only, and with no setup file, so the
// WebCrypto implementation under test is the browser's own.

import sjcl from '../src/sjcl/index.js';
import { beforeAll, describe, expect, test } from 'vitest';

import { i2osp, joinAll } from '../src/util.js';
import { PartiallyBlindRSA, getSuiteByName } from '../src/index.js';
import type { PartiallyBlindRSABackend } from '../src/index.js';
import { wasmBackend } from '../src/wasm/browser.js';

import { hexToUint8, privateKeyFromVector, publicKeyFromVector, uint8ToHex } from './util.js';
// https://datatracker.ietf.org/doc/html/draft-amjad-cfrg-partially-blind-rsa-02#name-test-vectors
import vectors from './testdata/test_vectors_partially_blind_rsa_draft_2.json' with { type: 'json' };

type Vector = (typeof vectors)[number];

let backend: PartiallyBlindRSABackend;

beforeAll(async () => {
    backend = await wasmBackend();
}, 60_000);

function preparedMessage(v: Vector): Uint8Array {
    // Every draft-02 vector uses deterministic preparation, so the prepared
    // message is the message with an empty prefix.
    return joinAll([hexToUint8(v.msg_prefix), hexToUint8(v.msg)]);
}

describe.each(vectors)('Browser_%#', (v: Vector) => {
    const info = hexToUint8(v.info);
    const sig = hexToUint8(v.sig);
    const inputMsg = preparedMessage(v);
    const kLen = Math.ceil(new sjcl.bn(v.n).bitLength() / 8);

    function suite(): PartiallyBlindRSA {
        return getSuiteByName(PartiallyBlindRSA, v.name, { supportsRSARAW: false, backend });
    }

    test('verify/accepts the test vector signature', async () => {
        const publicKey = await publicKeyFromVector(v);
        await expect(suite().verify(publicKey, sig, inputMsg, info)).resolves.toBe(true);
    });

    test('verify/rejects a tampered signature', async () => {
        const publicKey = await publicKeyFromVector(v);
        const tampered = sig.slice();
        tampered.set([sig[0] ^ 0x01], 0);
        await expect(suite().verify(publicKey, tampered, inputMsg, info)).resolves.toBe(false);
    });

    test('finalize/reproduces the test vector signature', async () => {
        const publicKey = await publicKeyFromVector(v);
        const inv = i2osp(new sjcl.bn(v.r).inverseMod(new sjcl.bn(v.n)), kLen);
        const signature = await suite().finalize(
            publicKey,
            inputMsg,
            info,
            hexToUint8(v.blind_sig),
            inv,
        );
        expect(uint8ToHex(signature)).toBe(v.sig);
    });
});

// One vector is enough for the end-to-end flow: it is the slowest test here,
// because issuance still runs in JavaScript.
describe('Browser client flow', () => {
    const v = vectors[0];

    test('prepare, blind, finalize and verify', async () => {
        const publicKey = await publicKeyFromVector(v);
        const privateKey = await privateKeyFromVector(v);
        const suite = getSuiteByName(PartiallyBlindRSA, v.name, {
            supportsRSARAW: false,
            backend,
        });
        const info = hexToUint8(v.info);

        const prepared = suite.prepare(hexToUint8(v.msg));
        const { blindedMsg, inv } = await suite.blind(publicKey, prepared, info);

        // Stands in for the issuer, which would not run in a browser.
        const blindSig = await suite.blindSign(privateKey, blindedMsg, info);

        const signature = await suite.finalize(publicKey, prepared, info, blindSig, inv);
        await expect(suite.verify(publicKey, signature, prepared, info)).resolves.toBe(true);
    }, 120_000);
});

// Canary for the browser bugs this backend works around, so that a fix is
// noticed rather than assumed:
// https://issues.chromium.org/issues/340178598
// https://bugzilla.mozilla.org/show_bug.cgi?id=1896444
describe('WebCrypto large public exponent', () => {
    const v = vectors[0];

    test('is still unsupported for the metadata-derived key', async () => {
        const publicKey = await publicKeyFromVector(v);
        const withoutBackend = getSuiteByName(PartiallyBlindRSA, v.name);
        const info = hexToUint8(v.info);
        const inputMsg = preparedMessage(v);

        const outcome = await withoutBackend
            .verify(publicKey, hexToUint8(v.sig), inputMsg, info)
            .then(
                (ok) => (ok ? 'verified' : 'returned false'),
                () => 'threw',
            );

        expect(
            outcome,
            'WebCrypto now verifies the metadata-derived key: update the README and drop this test',
        ).not.toBe('verified');
    });
});
