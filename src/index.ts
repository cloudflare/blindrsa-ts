// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

// RSA Blind Signature Protocol
//
// The RFC-9474 specifies (1) a protocol for computing RSA blind signatures
// using RSA-PSS encoding and (2) a family of variants for this protocol,
// denoted RSABSSA (RSA Blind Signature with Appendix).
//
// In order to facilitate deployment, it is defined in such a way that the
// resulting (unblinded) signature can be verified with a standard RSA-PSS
// library.
//
// RFC9474: https://www.rfc-editor.org/info/rfc9474

import {
    BlindRSA,
    PrepareType,
    type BlindRSAParams,
    type BlindRSAPlatformParams,
} from './blindrsa.js';

export { BlindRSA, type BlindRSAParams, type BlindRSAPlatformParams };

// Params allows to instantiate the RSABSSA protocol using BlindRSA class
// with one of the approved variants.
export const Params: Record<string, BlindRSAParams> = {
    RSABSSA_SHA384_PSS_Randomized: {
        name: 'RSABSSA-SHA384-PSS-Randomized',
        hash: 'SHA-384',
        saltLength: 48,
        prepareType: PrepareType.Randomized,
    },
    RSABSSA_SHA384_PSS_Deterministic: {
        name: 'RSABSSA-SHA384-PSS-Deterministic',
        hash: 'SHA-384',
        saltLength: 48,
        prepareType: PrepareType.Deterministic,
    },
    RSABSSA_SHA384_PSSZERO_Randomized: {
        name: 'RSABSSA-SHA384-PSSZERO-Randomized',
        hash: 'SHA-384',
        saltLength: 0,
        prepareType: PrepareType.Randomized,
    },
    RSABSSA_SHA384_PSSZERO_Deterministic: {
        name: 'RSABSSA-SHA384-PSSZERO-Deterministic',
        hash: 'SHA-384',
        saltLength: 0,
        prepareType: PrepareType.Deterministic,
    },
} as const;

// RSABSSA is used to access the variants of the protocol.
export const RSABSSA = {
    SHA384: {
        generateKey: (
            algorithm: Pick<RsaHashedKeyGenParams, 'modulusLength' | 'publicExponent'>,
        ): Promise<CryptoKeyPair> => BlindRSA.generateKey({ ...algorithm, hash: 'SHA-384' }),
        PSS: {
            Randomized: (params: BlindRSAPlatformParams = { supportsRSARAW: false }) =>
                new BlindRSA({ ...Params.RSABSSA_SHA384_PSS_Randomized, ...params }),
            Deterministic: (params: BlindRSAPlatformParams = { supportsRSARAW: false }) =>
                new BlindRSA({ ...Params.RSABSSA_SHA384_PSS_Deterministic, ...params }),
        },
        PSSZero: {
            Randomized: (params: BlindRSAPlatformParams = { supportsRSARAW: false }) =>
                new BlindRSA({ ...Params.RSABSSA_SHA384_PSSZERO_Randomized, ...params }),
            Deterministic: (params: BlindRSAPlatformParams = { supportsRSARAW: false }) =>
                new BlindRSA({ ...Params.RSABSSA_SHA384_PSSZERO_Deterministic, ...params }),
        },
    },
} as const;

export function getSuiteByName(
    name: string,
    params: BlindRSAPlatformParams = { supportsRSARAW: false },
): BlindRSA {
    for (const suiteParams of Object.values(Params)) {
        if (name.toLowerCase() === suiteParams.name.toLowerCase()) {
            return new BlindRSA({ ...suiteParams, ...params });
        }
    }

    throw new Error(`wrong suite name: ${name}`);
}
