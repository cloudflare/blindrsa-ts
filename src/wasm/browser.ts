// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

// Browser entry point for the WebAssembly backend. The module is fetched from
// the URL it ships at, which keeps this file free of any Node built-in so it
// can be bundled for the web.
//
// Where a module cannot be compiled at runtime, notably Cloudflare Workers,
// import the .wasm yourself and pass it to wasmBackend.

import { createWasmBackend, moduleURL } from './backend.js';

export type { WasmSource } from './backend.js';

/**
 * Loads the WebAssembly module and returns a backend for RSAPBSSA suites.
 *
 * ```ts
 * import { RSAPBSSA } from '@cloudflare/blindrsa-ts';
 * import { wasmBackend } from '@cloudflare/blindrsa-ts/wasm';
 *
 * const backend = await wasmBackend();
 * const suite = RSAPBSSA.SHA384.PSS.Deterministic({ supportsRSARAW: false, backend });
 * ```
 */
export const wasmBackend = createWasmBackend(() => Promise.resolve(moduleURL()));
