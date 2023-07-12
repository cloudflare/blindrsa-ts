// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

// Blind RSA draft 14
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures-14
import { RSABSSA, PrepareType } from './blindrsa'

export const SUITES = {
    SHA384: {
        PSS: {
            Randomized: () => new RSABSSA('SHA-384', 48, PrepareType.Randomized),
            Deterministic: () => new RSABSSA('SHA-384', 48, PrepareType.Deterministic)
        },
        PSSZero: {
            Randomized: () => new RSABSSA('SHA-384', 0, PrepareType.Randomized),
            Deterministic: () => new RSABSSA('SHA-384', 0, PrepareType.Deterministic)
        }
    }
} as const

export type API = RSABSSA

const SuiteNames: { [_: string]: () => API } = {
    'RSABSSA-SHA384-PSS-Randomized': SUITES.SHA384.PSS.Randomized,
    'RSABSSA-SHA384-PSSZERO-Randomized': SUITES.SHA384.PSSZero.Randomized,
    'RSABSSA-SHA384-PSS-Deterministic': SUITES.SHA384.PSS.Deterministic,
    'RSABSSA-SHA384-PSSZERO-Deterministic': SUITES.SHA384.PSSZero.Deterministic
} as const

export function getSuiteByName(name: string): API {
    for (const suite in SuiteNames) {
        if (name.toLowerCase() === suite.toLowerCase()) {
            return SuiteNames[suite as string]()
        }
    }

    throw new Error('wrong suite name')
}

export default SUITES
