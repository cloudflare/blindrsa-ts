// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

export type BlindOutput = { blindedMsg: Uint8Array; inv: Uint8Array };

// Everything a backend needs about the suite and the signer's public key.
// The key is passed as raw big-endian integers rather than a CryptoKey,
// because a backend is not required to use WebCrypto at all. `info` is the
// public metadata, and per-metadata key derivation is the backend's job.
export interface PartiallyBlindRSAContext {
    n: Uint8Array;
    e: Uint8Array;
    info: Uint8Array;
    hash: string;
    saltLength: number;
}

// The client half of RSAPBSSA: everything a holder of the public key does.
// Key generation and blind signing are the issuer's, and stay out.
//
// Implementations replace the default WebCrypto and SJCL code path, which
// browsers cannot run: the metadata-derived public exponent is about half the
// size of the modulus, and WebCrypto refuses exponents that large.
export interface PartiallyBlindRSABackend {
    // Identifies the implementation, for diagnostics.
    readonly id: string;

    // Blinds an already prepared message. Any randomized prefix is part of
    // preparedMsg, so a backend never has to know the preparation type.
    blind(ctx: PartiallyBlindRSAContext, preparedMsg: Uint8Array): Promise<BlindOutput>;

    // Unblinds a blind signature, and rejects if the result is not a valid
    // signature over preparedMsg.
    finalize(
        ctx: PartiallyBlindRSAContext,
        preparedMsg: Uint8Array,
        blindSig: Uint8Array,
        inv: Uint8Array,
    ): Promise<Uint8Array>;

    // Resolves false for any invalid or malformed signature. Failures of the
    // environment reject instead, so they are never mistaken for a bad
    // signature.
    verify(
        ctx: PartiallyBlindRSAContext,
        preparedMsg: Uint8Array,
        signature: Uint8Array,
    ): Promise<boolean>;
}
