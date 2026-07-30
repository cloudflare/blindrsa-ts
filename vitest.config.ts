import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        dir: './test',
        // Browser tests run under vitest.browser.config.ts instead: this setup
        // mocks WebCrypto through node:crypto, which a browser cannot load.
        exclude: ['**/*.browser.test.ts', '**/node_modules/**'],
        setupFiles: ['./test/vitest.setup-file.ts'],
        // src/wasm/pkg holds generated wasm-bindgen output, which the coverage
        // provider cannot parse.
        coverage: { enabled: true, include: ['src'], exclude: ['src/wasm/pkg/**'] },
    },
});
