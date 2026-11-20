import js from "@eslint/js";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";

const TURNKEY_PROOF_SEAM =
  "sdk/src/attestation/turnkey.ts";

export default [
  {
    ignores: ["**/dist/**", "**/node_modules/**"],
  },
  js.configs.recommended,
  {
    files: [
      "sdk/**/*.{ts,tsx}",
      "example/**/*.{ts,tsx}",
      "scripts/**/*.ts",
    ],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: "module",
        ecmaFeatures: { jsx: true },
      },
    },
    plugins: {
      "@typescript-eslint": tsPlugin,
    },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      "no-undef": "off",
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["@turnkey/*", "@turnkey/*/**"],
              message:
                "@turnkey/* imports are only allowed in the TVC Turnkey proof seam.",
            },
          ],
        },
      ],
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
  {
    files: [TURNKEY_PROOF_SEAM],
    rules: {
      "no-restricted-imports": "off",
    },
  },
  {
    files: ["example/turnkey.ts", "scripts/release-api.ts"],
    rules: {
      "no-restricted-imports": "off",
    },
  },
];
