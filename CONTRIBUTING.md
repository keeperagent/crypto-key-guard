# Contributing to crypto-key-guard

Thanks for your interest in contributing! This project helps protect crypto users from accidentally leaking private keys and seed phrases to AI/LLM services.

## Getting Started

```bash
git clone https://github.com/keeperagent/crypto-key-guard.git
cd crypto-key-guard
npm install
npm test
```

## Development

```bash
npm test            # run tests once
npm run test:watch  # run tests in watch mode
npm run build       # build the package
```

## How to Contribute

### Report Bugs

Open an issue with:
- What you expected to happen
- What actually happened
- Example input that caused the issue

### Add a New Chain / Key Format

1. Add the regex pattern to `src/patterns.ts`
2. Add test cases to `tests/detect.test.ts`
3. Update the supported chains table in `README.md`
4. Submit a pull request

### Improve Seed Phrase Detection

The BIP39 wordlist is in `src/wordlist.ts`. If you want to add support for other languages (Chinese, Japanese, Korean, Spanish, etc.), add a new wordlist file and update the detection logic.

### Reduce False Positives

If you find a case where normal text is incorrectly flagged as a secret, please open an issue with the text that triggered the false positive. This helps us improve the patterns.

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Add tests for new patterns or detection logic
- Run `npm test` and make sure all tests pass before submitting
- Update README if adding new chains or changing the API

## Code Structure

```
src/
├── index.ts      # public exports
├── detect.ts     # detect() — find secrets in text
├── redact.ts     # redact() / restore() — replace secrets with tokens
├── guard.ts      # guard() — block text containing secrets
├── check.ts      # isPrivateKey() / isSeedPhrase() / containsSecret()
├── patterns.ts   # regex patterns per chain
└── wordlist.ts   # BIP39 English wordlist (2048 words)
```

## Testing

All test keys in `tests/` are generated for testing purposes only. Never use real private keys in tests.

```bash
npm test
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
