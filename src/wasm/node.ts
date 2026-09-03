// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

// Node entry point for the WebAssembly backend. A file: URL cannot be
// fetched, so the module is read from disk. This file is selected through the
// "node" export condition, keeping node:fs out of browser bundles.

import { createWasmBackend, moduleURL, type WasmSource } from './backend.js';

export type { WasmSource } from './backend.js';

async function readModule(): Promise<WasmSource> {
    const { readFile } = await import('node:fs/promises');
    const bytes = await readFile(moduleURL());
    return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

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
export const wasmBackend = createWasmBackend(readModule);
