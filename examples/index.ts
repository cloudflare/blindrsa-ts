// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { blindRSAExample } from './blindrsa.js'
import { webcrypto } from 'node:crypto'
import { SUITES } from '../src/index.js'

if (typeof crypto === 'undefined') {
    global.crypto = webcrypto as unknown as Crypto
}

async function examples() {
    await blindRSAExample(SUITES.SHA384.PSS.Randomized())
    await blindRSAExample(SUITES.SHA384.PSSZero.Randomized())
    await blindRSAExample(SUITES.SHA384.PSS.Deterministic())
    await blindRSAExample(SUITES.SHA384.PSSZero.Deterministic())
}

examples().catch((e: Error) => {
    console.log(`Error: ${e.message}`)
    console.log(`Stack: ${e.stack}`)
    process.exit(1)
})
