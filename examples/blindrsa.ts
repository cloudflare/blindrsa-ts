// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import type { BlindRSA } from '../src/index.js';

// Example: BlindRSA protocol execution.
export async function blindRSAExample(suite: BlindRSA) {
    // Setup: Generate server keypair.
    const { privateKey, publicKey } = await suite.generateKey(
        {
            publicExponent: Uint8Array.from([1, 0, 1]),
            modulusLength: 2048,
        },
        true,
        ['sign', 'verify'],
    );

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
    const message = new TextEncoder().encode(msgString);
    const preparedMsg = suite.prepare(message);
    const { blindedMsg, inv } = await suite.blind(publicKey, preparedMsg);
    //
    // The client sends the blinded message to the server.
    //             blindedMsg
    //       ------------------>>
    //                                              Server
    // Step 2: Once the server received the blinded message,
    // it responds to the client with a blind signature.
    //
    //          blindSignature = blindSign(privateKey, blindedMsg)
    const blindSignature = await suite.blindSign(privateKey, blindedMsg);
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
    // signature = finalize(publicKey, preparedMsg, blindSignature, inv)
    const signature = await suite.finalize(publicKey, preparedMsg, blindSignature, inv);
    //
    // Step 4: Anyone can verify the signature using the
    // sever's public key.
    const isValid = await suite.verify(publicKey, signature, preparedMsg);

    console.log(`Example BlindRSA - Suite: ${suite}`);
    console.log(`input_msg: (${msgString.length} bytes): ${msgString}`);
    console.log(
        `signature: (${signature.length} bytes): ${Buffer.from(signature).toString('hex')}`,
    );
    console.log(`Signature is valid? ${isValid}\n`);
}
