// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

// Blind RSA draft 14
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures-14
import { BlindRSA, PrepareType, type BlindRSAParams } from './blindrsa.js';

export { BlindRSA, type BlindRSAParams };

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

export const RSABSSA = {
    SHA384: {
        generateKey: (
            algorithm: Pick<RsaHashedKeyGenParams, 'modulusLength' | 'publicExponent'>,
        ): Promise<CryptoKeyPair> => BlindRSA.generateKey({ ...algorithm, hash: 'SHA-384' }),
        PSS: {
            Randomized: () => new BlindRSA(Params.RSABSSA_SHA384_PSS_Randomized),
            Deterministic: () => new BlindRSA(Params.RSABSSA_SHA384_PSS_Deterministic),
        },
        PSSZero: {
            Randomized: () => new BlindRSA(Params.RSABSSA_SHA384_PSSZERO_Randomized),
            Deterministic: () => new BlindRSA(Params.RSABSSA_SHA384_PSSZERO_Deterministic),
        },
    },
} as const;

export function getSuiteByName(name: string): BlindRSA {
    for (const suiteParams of Object.values(Params)) {
        if (name.toLowerCase() === suiteParams.name.toLowerCase()) {
            return new BlindRSA(suiteParams);
        }
    }

    throw new Error(`wrong suite name: ${name}`);
}
