# ejmorgan-jwt

[![Node.js CI](https://github.com/everettmorgan/jwt/actions/workflows/node.js.yml/badge.svg)](https://github.com/everettmorgan/jwt/actions/workflows/node.js.yml)
[![CodeQL](https://github.com/everettmorgan/jwt/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/everettmorgan/jwt/actions/workflows/codeql-analysis.yml)

A small HMAC JWT implementation for Node.js 22 and newer.

## Overview

`ejmorgan-jwt` signs, decodes, and verifies compact JSON Web Tokens with the
HMAC algorithms this package actually implements: `HS256`, `HS384`, and
`HS512`.

It does not implement RSA, ECDSA, or `none` algorithms.

## Features

- Standards-compatible JOSE algorithm names.
- Base64url-encoded signatures without padding.
- NumericDate validation in seconds for `exp`, `nbf`, and `iat`.
- Constant-time signature comparison.
- Stable `JwtError` codes for expected failure modes.
- Zero runtime dependencies.

## Requirements

- Node.js 22 or newer.
- CommonJS runtime or bundler compatibility.

## Installation

```sh
npm install ejmorgan-jwt
```

```sh
yarn add ejmorgan-jwt
```

## Quick Start

```javascript
const { sign, decode, verify, JwtError } = require('ejmorgan-jwt');

const secret = 'my-secret';

const token = sign(
  {
    aud: 'api',
    sub: 'user-123',
    exp: Math.floor(Date.now() / 1000) + 60,
  },
  secret,
  { algorithm: 'HS256' },
);

const decoded = decode(token);
console.log(decoded.header.alg);
console.log(decoded.payload.sub);

try {
  const verified = verify(token, secret, {
    algorithms: ['HS256'],
    clockTolerance: 5,
  });

  console.log(verified.payload.aud);
} catch (error) {
  if (error instanceof JwtError) {
    console.error(error.code);
  }

  throw error;
}
```

## API

### `sign(payload, secret, options?)`

Returns a compact JWT string.

```typescript
function sign(payload: JwtPayload, secret: JwtSecret, options?: SignOptions): string;
```

- `payload`: JSON object containing JWT claims.
- `secret`: HMAC secret accepted by Node's `crypto.createHmac`.
- `options.algorithm`: `HS256`, `HS384`, or `HS512`. Defaults to `HS256`.
- `options.header`: additional header parameters. `alg` is always controlled by
  `options.algorithm`.

### `decode(token)`

Parses a JWT without verifying its signature.

```typescript
function decode(token: string): DecodedJwt;
```

Returns:

```typescript
interface DecodedJwt {
  header: JwtHeader;
  payload: JwtPayload;
  signature: string;
  signingInput: string;
  token: string;
}
```

### `verify(token, secret, options?)`

Verifies the signature and registered time claims, then returns the decoded JWT.

```typescript
function verify(token: string, secret: JwtSecret, options?: VerifyOptions): DecodedJwt;
```

- `options.algorithms`: allowed algorithms. Defaults to all supported HMAC
  algorithms.
- `options.clockTimestamp`: current NumericDate in seconds. Defaults to the
  current system time.
- `options.clockTolerance`: allowed clock skew in seconds. Defaults to `0`.

## Error Codes

JWT failures throw `JwtError` with one of these stable `code` values:

| Code | Meaning |
| --- | --- |
| `malformed_token` | The token is not three non-empty dot-separated segments or does not contain JSON objects. |
| `invalid_base64url` | A token segment is not valid base64url. |
| `invalid_json` | The header or payload segment is not valid JSON. |
| `unsupported_algorithm` | The token uses an unsupported or disallowed algorithm. |
| `bad_signature` | The signature does not match the signing input. |
| `expired` | The `exp` claim is at or before the verification time. |
| `not_before` | The `nbf` claim is after the verification time. |
| `issued_at_future` | The `iat` claim is after the verification time. |
| `invalid_claim` | A registered NumericDate claim is not a finite number. |
| `invalid_option` | A verification option is invalid. |

## Development

Install dependencies:

```sh
corepack enable
yarn install --immutable
```

Run the full local check:

```sh
yarn check
```

Useful commands:

```sh
yarn lint
yarn typecheck
yarn test
yarn coverage
yarn build
npm pack --dry-run
```

## Security

This package only supports HMAC JWT algorithms. Do not use it for tokens that
must be signed with asymmetric keys.

Report security issues privately to the repository maintainer.

## Support

Open an issue in the GitHub repository for bugs, usage questions, or feature
requests.

## License

MIT
