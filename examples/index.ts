// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { webcrypto } from 'node:crypto';

import { RSABSSA, RSAPBSSA } from '../src/index.js';
import { blindRSAExample } from './blindrsa.js';
import { partiallyBlindRSAExample } from './partially_blindrsa.js';

if (typeof crypto === 'undefined') {
    Object.assign(global, { crypto: webcrypto });
}

async function examples() {
    await blindRSAExample(RSABSSA.SHA384.PSS.Randomized());
    await blindRSAExample(RSABSSA.SHA384.PSSZero.Randomized());
    await blindRSAExample(RSABSSA.SHA384.PSS.Deterministic());
    await blindRSAExample(RSABSSA.SHA384.PSSZero.Deterministic());

    await partiallyBlindRSAExample(RSAPBSSA.SHA384.PSS.Randomized());
    await partiallyBlindRSAExample(RSAPBSSA.SHA384.PSSZero.Randomized());
    await partiallyBlindRSAExample(RSAPBSSA.SHA384.PSS.Deterministic());
    await partiallyBlindRSAExample(RSAPBSSA.SHA384.PSSZero.Deterministic());
}

examples().catch((e: Error) => {
    console.log(`Error: ${e.message}`);
    console.log(`Stack: ${e.stack}`);
    process.exit(1);
});
