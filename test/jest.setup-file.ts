// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

// Mocking crypto with NodeJS WebCrypto module only for tests.
import { webcrypto } from 'node:crypto';
import { RSABSSA } from '../src';

// RSA-RAW is not supported by WebCrypto, so we need to mock it.
// blindSign operation is similar for deterministic and randomized variants, and salt length is not used during this operation.
// It matches cloudflare/workerd implementation https://github.com/cloudflare/workerd/blob/6b63c701e263a311c2a3ce64e2aeada69afc32a1/src/workerd/api/crypto-impl-asymmetric.c%2B%2B#L827-L868
async function mockSign(
    algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams,
    key: CryptoKey,
    data: Uint8Array,
): Promise<ArrayBuffer> {
    if (
        algorithm === 'RSA-RAW' ||
        (typeof algorithm !== 'string' && algorithm?.name === 'RSA-RAW')
    ) {
        const algorithmName = key.algorithm.name;
        if (algorithmName !== 'RSA-RAW') {
            throw new Error(`Invalid key algorithm: ${algorithmName}`);
        }
        key.algorithm.name = 'RSA-PSS';
        try {
            return RSABSSA.SHA384.PSSZero.Deterministic().blindSign(key, data);
        } finally {
            key.algorithm.name = algorithmName;
        }
    }
    return webcrypto.subtle.sign(algorithm, key, data);
}

if (typeof crypto === 'undefined') {
    Object.assign(global, { crypto: webcrypto });
}

crypto.subtle.sign = mockSign;
