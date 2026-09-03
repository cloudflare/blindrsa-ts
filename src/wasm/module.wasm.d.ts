// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

// Type of the "./wasm/module.wasm" export, which a bundler that compiles
// WebAssembly at build time, as Cloudflare Workers does, turns into a
// WebAssembly.Module. TypeScript cannot type a .wasm target on its own, and the
// declaration wasm-bindgen ships next to the module describes the raw wasm
// exports, not a default import.
//
// The subpath ends in .wasm because the Workers bundler installs its wasm
// loader by matching the import specifier, not the resolved path.

declare const wasmModule: WebAssembly.Module;
export default wasmModule;
