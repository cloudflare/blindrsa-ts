import eslintJS from '@eslint/js'
import eslintTS from 'typescript-eslint'
import pluginPrettier from 'eslint-plugin-prettier/recommended'
import pluginSecurity from 'eslint-plugin-security'
import pluginVitest from 'eslint-plugin-vitest'

export default eslintTS.config(
    eslintJS.configs.recommended,
    ...eslintTS.configs.strictTypeChecked,
    pluginVitest.configs.recommended,
    pluginSecurity.configs.recommended,
    {
        ignores: [
            'vitest.config.ts',
            'eslint.config.mjs',
            'coverage/*',
            'src/sjcl/index.js',
            'src/sjcl/index.d.ts',
            'lib/*'
        ]
    },
    {
        languageOptions: {
            sourceType: 'module',
            parserOptions: {
                project: true,
                tsconfigRootDir: import.meta.dirname
            }
        },
        rules: {
            '@typescript-eslint/no-namespace': 'warn',
            "@typescript-eslint/no-unused-vars": [
                "error",
                {
                    "args": "all",
                    "argsIgnorePattern": "^_",
                    "caughtErrors": "all",
                    "varsIgnorePattern": "^_"
                }
            ],
            '@typescript-eslint/consistent-type-imports': 'error',
            '@typescript-eslint/consistent-type-exports': 'error',
            '@typescript-eslint/restrict-template-expressions': 'off'
        }
    },
    pluginPrettier
)
