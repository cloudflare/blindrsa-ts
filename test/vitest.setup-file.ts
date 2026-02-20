// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

// Mocking crypto with NodeJS WebCrypto module only for tests.
import { webcrypto } from 'node:crypto';
import { RSABSSA } from '../src/index.js';

if (typeof crypto === 'undefined') {
    Object.assign(global, { crypto: webcrypto });
}

// RSA-RAW is not supported by WebCrypto, so we need to mock it.
// blindSign operation is similar for deterministic and randomized variants, and salt length is not used during this operation.
// It matches cloudflare/workerd implementation https://github.com/cloudflare/workerd/blob/6b63c701e263a311c2a3ce64e2aeada69afc32a1/src/workerd/api/crypto-impl-asymmetric.c%2B%2B#L827-L868
// eslint-disable-next-line @typescript-eslint/unbound-method
const parentSign = crypto.subtle.sign;
async function mockSign(
    algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams,
    key: CryptoKey,
    data: ArrayBuffer,
): Promise<ArrayBuffer> {
    if (
        algorithm === 'RSA-RAW' ||
        (typeof algorithm !== 'string' && algorithm.name === 'RSA-RAW')
    ) {
        const algorithmName = key.algorithm.name;
        if (algorithmName !== 'RSA-RAW') {
            throw new Error(`Invalid key algorithm: ${algorithmName}`);
        }
        key.algorithm.name = 'RSA-PSS';
        try {
            // await is needed here because if the promised is returned, the algorithmName could be restored before the key is used, causing an error
            const data_u8 = new Uint8Array(data);
            const blindSig = await RSABSSA.SHA384.PSSZero.Deterministic().blindSign(key, data_u8);
            return blindSig.slice().buffer;
        } finally {
            key.algorithm.name = algorithmName;
        }
    }

    // webcrypto calls crypto, which is mocked. We need to restore the original implementation.
    crypto.subtle.sign = parentSign;
    const res = crypto.subtle.sign(algorithm, key, data);
    await res.finally(() => {
        crypto.subtle.sign = mockSign;
    });
    return res;
}
crypto.subtle.sign = mockSign;

// eslint-disable-next-line @typescript-eslint/unbound-method
const parentImportKey = crypto.subtle.importKey;
async function mockImportKey(
    format: KeyFormat,
    keyData: JsonWebKey | BufferSource,
    algorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: KeyUsage[],
): Promise<CryptoKey> {
    crypto.subtle.importKey = parentImportKey;
    try {
        if (format === 'jwk') {
            return await crypto.subtle.importKey(
                format,
                keyData as JsonWebKey,
                algorithm,
                extractable,
                keyUsages,
            );
        }
        const data: BufferSource = keyData as BufferSource;
        if (
            algorithm === 'RSA-RAW' ||
            (!(typeof algorithm === 'string') && algorithm.name === 'RSA-RAW')
        ) {
            if (typeof algorithm === 'string') {
                algorithm = { name: 'RSA-PSS' };
            } else {
                algorithm = { ...algorithm, name: 'RSA-PSS' };
            }
            const key = await crypto.subtle.importKey(
                format,
                data,
                algorithm,
                extractable,
                keyUsages,
            );
            key.algorithm.name = 'RSA-RAW';
            return key;
        }
        return await crypto.subtle.importKey(format, data, algorithm, extractable, keyUsages);
    } finally {
        crypto.subtle.importKey = mockImportKey;
    }
}
crypto.subtle.importKey = mockImportKey;
