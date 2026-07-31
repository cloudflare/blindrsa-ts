// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

// WebAssembly backend for the RSAPBSSA client operations.
//
// Browsers cannot run these with WebCrypto: partially blind RSA derives a
// public exponent about half the size of the modulus, and WebCrypto rejects
// exponents that large. This backend runs blinding, finalization and
// verification in the blind-rsa-signatures Rust crate instead, which is also
// what the Rust Privacy Pass implementation uses.
//
// Locating the module differs per platform, so this file holds everything
// else and the entry points in node.ts and browser.ts supply a resolver.

import type {
    BlindOutput,
    PartiallyBlindRSABackend,
    PartiallyBlindRSAContext,
} from '../backend.js';

import init, { blind, finalize, verify } from './pkg/blindrsa_wasm.js';

// Where to read the WebAssembly module from.
//
// Supply this wherever the module cannot be located automatically. On
// Cloudflare Workers, where compiling a module at runtime is not allowed,
// import the .wasm file and pass the resulting WebAssembly.Module.
export type WasmSource = WebAssembly.Module | BufferSource | URL;

// Resolves the module shipped alongside this package.
export type WasmSourceResolver = () => Promise<WasmSource>;

const SUPPORTED_HASH = 'SHA-384';

function assertSupported(ctx: PartiallyBlindRSAContext): void {
    if (ctx.hash.toLowerCase() !== SUPPORTED_HASH.toLowerCase()) {
        throw new Error(`hash is not ${SUPPORTED_HASH}`);
    }
    if (ctx.saltLength !== 0 && ctx.saltLength !== 48) {
        throw new Error(`unsupported salt length: ${ctx.saltLength}`);
    }
}

// The URL of the module shipped next to this file, for a resolver to read or
// fetch.
export function moduleURL(): URL {
    return new URL('./pkg/blindrsa_wasm_bg.wasm', import.meta.url);
}

const backend: PartiallyBlindRSABackend = {
    id: 'wasm',

    // eslint-disable-next-line @typescript-eslint/require-await
    async blind(ctx: PartiallyBlindRSAContext, preparedMsg: Uint8Array): Promise<BlindOutput> {
        assertSupported(ctx);
        const out = blind(ctx.n, ctx.e, ctx.info, preparedMsg, ctx.saltLength);
        // Blinded message and inverse, each of modulus length. Split on the
        // modulus rather than on half the output, so that an unexpected length
        // is an error here and not part of the secret inverse travelling to
        // the issuer inside the blinded message.
        const kLen = ctx.n.length;
        if (out.length !== 2 * kLen) {
            throw new Error('backend returned a blinding of the wrong size');
        }
        // Copied out rather than sliced as views: the inverse is secret and the
        // blinded message is sent to the issuer, so they must not share a
        // buffer that a caller could serialize whole.
        return { blindedMsg: out.slice(0, kLen), inv: out.slice(kLen) };
    },

    // eslint-disable-next-line @typescript-eslint/require-await
    async finalize(
        ctx: PartiallyBlindRSAContext,
        preparedMsg: Uint8Array,
        blindSig: Uint8Array,
        inv: Uint8Array,
    ): Promise<Uint8Array> {
        assertSupported(ctx);
        return finalize(ctx.n, ctx.e, ctx.info, preparedMsg, blindSig, inv, ctx.saltLength);
    },

    // eslint-disable-next-line @typescript-eslint/require-await
    async verify(
        ctx: PartiallyBlindRSAContext,
        preparedMsg: Uint8Array,
        signature: Uint8Array,
    ): Promise<boolean> {
        assertSupported(ctx);
        return verify(ctx.n, ctx.e, ctx.info, preparedMsg, signature, ctx.saltLength);
    },
};

/**
 * Builds the loader exported by the platform entry points.
 *
 * The module is instantiated once per process; a later call with a different
 * source reuses the first instantiation. A failed load is not cached, so a
 * caller can retry with an explicit source.
 */
export function createWasmBackend(
    resolveDefaultSource: WasmSourceResolver,
): (source?: WasmSource) => Promise<PartiallyBlindRSABackend> {
    let loaded: Promise<PartiallyBlindRSABackend> | undefined;

    const load = async (source?: WasmSource): Promise<PartiallyBlindRSABackend> => {
        const module_or_path = source ?? (await resolveDefaultSource());
        await init({ module_or_path });
        return backend;
    };

    return (source?: WasmSource): Promise<PartiallyBlindRSABackend> => {
        loaded ??= load(source).catch((e: unknown) => {
            loaded = undefined;
            throw e;
        });
        return loaded;
    };
}
