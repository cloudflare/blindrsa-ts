import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        dir: './test',
        setupFiles: ['./test/vitest.setup-file.ts'],
        coverage: { enabled: true, include: ['src'] },
    },
});
