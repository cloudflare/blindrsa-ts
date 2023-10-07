// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

// Blind RSA draft 14
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures-14
import { BlindRSA, PrepareType } from './blindrsa.js';

export type { BlindRSA };

export const SUITES = {
    SHA384: {
        PSS: {
            Randomized: () => new BlindRSA('SHA-384', 48, PrepareType.Randomized),
            Deterministic: () => new BlindRSA('SHA-384', 48, PrepareType.Deterministic),
        },
        PSSZero: {
            Randomized: () => new BlindRSA('SHA-384', 0, PrepareType.Randomized),
            Deterministic: () => new BlindRSA('SHA-384', 0, PrepareType.Deterministic),
        },
    },
} as const;

export function getSuiteByName(name: string): BlindRSA {
    const lstSuites = [
        SUITES.SHA384.PSS.Randomized,
        SUITES.SHA384.PSSZero.Randomized,
        SUITES.SHA384.PSS.Deterministic,
        SUITES.SHA384.PSSZero.Deterministic,
    ];

    const nameLowerCaee = name.toLowerCase();
    for (const suite of lstSuites) {
        const ss = suite();
        if (nameLowerCaee === ss.toString().toLowerCase()) {
            return ss;
        }
    }

    throw new Error('wrong suite name');
}
