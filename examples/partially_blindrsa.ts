// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0
import sjcl from 'sjcl';
import { Buffer } from 'node:buffer';
import { generatePrimeSync } from 'node:crypto';

import type { PartiallyBlindRSA } from '../src/index.js';

function hexNumToB64URL(x: string): string {
    if (x.startsWith('0x')) {
        x = x.slice(2);
    }
    return Buffer.from(x, 'hex').toString('base64url');
}

async function preGeneratedKeys(extractable = true): Promise<CryptoKeyPair> {
    const draft2_first_key: Record<string, string> = {
        p: 'dcd90af1be463632c0d5ea555256a20605af3db667475e190e3af12a34a3324c46a3094062c59fb4b249e0ee6afba8bee14e0276d126c99f4784b23009bf6168ff628ac1486e5ae8e23ce4d362889de4df63109cbd90ef93db5ae64372bfe1c55f832766f21e94ea3322eb2182f10a891546536ba907ad74b8d72469bea396f3',
        q: 'f8ba5c89bd068f57234a3cf54a1c89d5b4cd0194f2633ca7c60b91a795a56fa8c8686c0e37b1c4498b851e3420d08bea29f71d195cfbd3671c6ddc49cf4c1db5b478231ea9d91377ffa98fe95685fca20ba4623212b2f2def4da5b281ed0100b651f6db32112e4017d831c0da668768afa7141d45bbc279f1e0f8735d74395b3',
        d: '4e21356983722aa1adedb084a483401c1127b781aac89eab103e1cfc52215494981d18dd8028566d9d499469c25476358de23821c78a6ae43005e26b394e3051b5ca206aa9968d68cae23b5affd9cbb4cb16d64ac7754b3cdba241b72ad6ddfc000facdb0f0dd03abd4efcfee1730748fcc47b7621182ef8af2eeb7c985349f62ce96ab373d2689baeaea0e28ea7d45f2d605451920ca4ea1f0c08b0f1f6711eaa4b7cca66d58a6b916f9985480f90aca97210685ac7b12d2ec3e30a1c7b97b65a18d38a93189258aa346bf2bc572cd7e7359605c20221b8909d599ed9d38164c9c4abf396f897b9993c1e805e574d704649985b600fa0ced8e5427071d7049d',
        e: '010001',
        n: 'd6930820f71fe517bf3259d14d40209b02a5c0d3d61991c731dd7da39f8d69821552e2318d6c9ad897e603887a476ea3162c1205da9ac96f02edf31df049bd55f142134c17d4382a0e78e275345f165fbe8e49cdca6cf5c726c599dd39e09e75e0f330a33121e73976e4facba9cfa001c28b7c96f8134f9981db6750b43a41710f51da4240fe03106c12acb1e7bb53d75ec7256da3fddd0718b89c365410fce61bc7c99b115fb4c3c318081fa7e1b65a37774e8e50c96e8ce2b2cc6b3b367982366a2bf9924c4bafdb3ff5e722258ab705c76d43e5f1f121b984814e98ea2b2b8725cd9bc905c0bc3d75c2a8db70a7153213c39ae371b2b5dc1dafcb19d6fae9',
    };
    draft2_first_key.dp = new sjcl.bn(draft2_first_key.d)
        .mod(new sjcl.bn(draft2_first_key.p).sub(new sjcl.bn(1)))
        .toString();
    draft2_first_key.dq = new sjcl.bn(draft2_first_key.d)
        .mod(new sjcl.bn(draft2_first_key.q).sub(new sjcl.bn(1)))
        .toString();
    draft2_first_key.qi = new sjcl.bn(draft2_first_key.q)
        .inverseMod(new sjcl.bn(draft2_first_key.p))
        .toString();

    const params = Object.fromEntries(
        Object.entries(draft2_first_key).map(([k, v]) => [k, hexNumToB64URL(v)]),
    );
    const { n, e } = params;
    const publicKey = await crypto.subtle.importKey(
        'jwk',
        { kty: 'RSA', ext: true, n, e },
        { name: 'RSA-PSS', hash: 'SHA-384' },
        extractable,
        ['verify'],
    );

    const privateKey = await crypto.subtle.importKey(
        'jwk',
        { kty: 'RSA', ext: true, ...params },
        { name: 'RSA-PSS', hash: 'SHA-384' },
        extractable,
        ['sign'],
    );
    return { privateKey, publicKey };
}

enum KeyGenerationType {
    PreGenerated,
    NodeJS,
    BuiltIn,
}

function loadKeys(
    suite: PartiallyBlindRSA,
    keyGeneration: KeyGenerationType,
): Promise<CryptoKeyPair> {
    const algorithm = {
        publicExponent: Uint8Array.from([1, 0, 1]),
        modulusLength: 2048, // [WARNING:] while this can be slow, DO NOT replace modulusLength a number below 2048. This would make your cryptography insecure.
    };
    switch (keyGeneration) {
        case KeyGenerationType.PreGenerated:
            return preGeneratedKeys();
        case KeyGenerationType.NodeJS:
            return suite.generateKey(algorithm, (length: number) =>
                generatePrimeSync(length, { safe: true, bigint: true }),
            );
        case KeyGenerationType.BuiltIn:
            return suite.generateKey(algorithm);
    }
}

// Example: PartiallyBlindRSA protocol execution.
export async function partiallyBlindRSAExample(suite: PartiallyBlindRSA) {
    // Setup: Generate server keypair.
    //
    // Key generation requires generating safe prime numbers.
    // The library provides the `generateKey` method for completeness, but it is slow.
    // Be aware of this before use it in a performance-critical application.
    // Alternatively, use node crypto library to generate safe primes.
    const { privateKey, publicKey } = await loadKeys(suite, KeyGenerationType.NodeJS);

    // Client                                       Server
    // ====================================================
    // Step 1: The client prepares arbitrary input to be
    // blindly-signed by the server. The blind method
    // produces a blinded message and an inverse string
    // to be used during finalization.
    //
    // Client
    // blindedMsg, inv = Blind(publicKey, preparedMsg)
    const msgString = 'Alice and Bob';
    const infoString = 'Public metadata';
    const message = new TextEncoder().encode(msgString);
    const info = new TextEncoder().encode(infoString);
    const preparedMsg = suite.prepare(message);
    const { blindedMsg, inv } = await suite.blind(publicKey, preparedMsg, info);
    //
    // The client sends the blinded message to the server.
    //             blindedMsg
    //       ------------------>>
    //                                              Server
    // Step 2: Once the server received the blinded message,
    // it responds to the client with a blind signature.
    //
    //          blindSignature = blindSign(privateKey, blindedMsg, info)
    const blindSignature = await suite.blindSign(privateKey, blindedMsg, info);
    //
    // The server sends the blinded signature to the client.
    //            blindSignature
    //       <<------------------
    //
    // Client
    // Step 3: The client produces the final signature with
    // the server's blinded signature and the inverse data
    // from the first step.
    //
    // signature = finalize(publicKey, preparedMsg, info, blindSignature, inv)
    const signature = await suite.finalize(publicKey, preparedMsg, info, blindSignature, inv);
    //
    // Step 4: Anyone can verify the signature using the
    // server's public key.
    const isValid = await suite.verify(publicKey, signature, preparedMsg, info);

    console.log(`Example Partially Blind RSA - Suite: ${suite}`);
    console.log(`input_msg: (${msgString.length} bytes): ${msgString}`);
    console.log(`input_info: (${infoString.length} bytes): ${infoString}`);
    console.log(
        `signature: (${signature.length} bytes): ${Buffer.from(signature).toString('hex')}`,
    );
    console.log(`Signature is valid? ${isValid}\n`);
}
