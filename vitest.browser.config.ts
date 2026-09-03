import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

// Runs the browser suite in a real browser. Only *.browser.test.ts files are
// included: the Node suite mocks WebCrypto through node:crypto, and the prime
// generation tests are far too slow for a browser run.
export default defineConfig({
    test: {
        dir: './test',
        include: ['**/*.browser.test.ts'],
        browser: {
            enabled: true,
            headless: true,
            provider: playwright(),
            instances: [{ browser: 'chromium' }],
        },
    },
});
