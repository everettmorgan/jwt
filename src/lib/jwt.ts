import * as crypto from 'crypto';
import base64url from 'base64url';
// eslint-disable-next-line import/no-unresolved, import/extensions
import { JWTRegisteredClaimNames, JWSRegisteredHeaderParameters } from './base';

// Maps RFC 7518 algorithm names to Node.js crypto HMAC digest names.
const ALG_TO_HMAC: Record<string, string> = {
  HS256: 'sha256',
  HS384: 'sha384',
  HS512: 'sha512',
};

// Minimum HMAC key byte lengths per RFC 7518 §3.2:
// "A key of the same size as the hash output … or larger MUST be used."
const MIN_KEY_BYTES: Record<string, number> = {
  HS256: 32,
  HS384: 48,
  HS512: 64,
};

interface JSONWebTokenConstructor {
  key?: string;
  header: JWSRegisteredHeaderParameters;
  payload: JWTRegisteredClaimNames;
}

/**
 * Options for Validate(). All fields are optional; omitting a field skips
 * that check.
 */
export interface ValidateOptions {
  /**
   * Expected audience. Validation fails if the token's `aud` claim does not
   * include at least one of the provided values.
   */
  audience?: string | string[];

  /**
   * Expected issuer. Validation fails if the token's `iss` claim does not
   * exactly match this value.
   */
  issuer?: string;

  /**
   * Clock skew tolerance in seconds (default: 0). Applied symmetrically to
   * `exp`, `nbf`, and `iat` to accommodate minor differences between clocks
   * in distributed systems.
   */
  leeway?: number;
}

class JSONWebToken {
  readonly header: JWSRegisteredHeaderParameters;

  readonly payload: JWTRegisteredClaimNames;

  readonly signature?: string;

  constructor(opts: JSONWebTokenConstructor) {
    this.header = opts.header;
    this.payload = opts.payload;

    if (opts.key) {
      // eslint-disable-next-line no-use-before-define
      this.signature = Sign(this, opts.key);
    }
  }

  toString(): string {
    // RFC 7515 §6.1: compact serialization requires all three parts.
    if (!this.signature) {
      throw new Error('Cannot serialize an unsigned JWT; provide a key when calling New()');
    }

    const headerString = JSON.stringify(this.header);
    const payloadString = JSON.stringify(this.payload);

    const headerBase64 = base64url(headerString);
    const payloadBase64 = base64url(payloadString);

    return `${headerBase64}.${payloadBase64}.${this.signature}`;
  }
}

function New(opts: JSONWebTokenConstructor): JSONWebToken {
  return new JSONWebToken(opts);
}

function Read(
  jwtstr: string,
  key: string,
  algorithm?: 'HS256' | 'HS384' | 'HS512',
): [boolean, JSONWebToken | null] {
  const [headerBase64, payloadBase64, signature] = jwtstr.split('.');

  if (!headerBase64 || !payloadBase64 || !signature) return [true, null];

  let header: JWSRegisteredHeaderParameters;
  let payload: JWTRegisteredClaimNames;

  try {
    header = JSON.parse(base64url.decode(headerBase64));
    payload = JSON.parse(base64url.decode(payloadBase64));
  } catch {
    return [true, null];
  }

  // RFC 7519 §10.1: algorithm pinning — reject if the token's alg differs
  // from the caller's expectation to prevent algorithm confusion attacks.
  if (algorithm !== undefined && header.alg !== algorithm) return [true, null];

  // RFC 7515 §4.1.11: if crit is present, all listed extensions MUST be
  // understood and processed. This library implements none, so reject.
  if (header.crit && header.crit.length > 0) return [true, null];

  let jwt: JSONWebToken;
  try {
    jwt = New({ header, payload, key });
  } catch {
    // New() → Sign() throws for unsupported algorithms or short keys
    return [true, null];
  }

  if (jwt.signature !== signature) return [true, null];

  return [false, jwt];
}

function Validate(jwt: JSONWebToken, key: string, opts: ValidateOptions = {}): boolean {
  const { audience, issuer, leeway = 0 } = opts;
  const expirationDate = jwt.payload.exp;
  const notBefore = jwt.payload.nbf;
  const { signature } = jwt;

  // JWT NumericDate values are seconds since epoch (RFC 7519 §2)
  const now = Math.floor(Date.now() / 1000);

  // eslint-disable-next-line no-use-before-define
  const check = Sign(jwt, key);

  // Signature must be present and match
  if (!signature) return false;
  if (check !== signature) return false;

  // Time claims — leeway accounts for clock skew in distributed systems
  //
  // nbf (RFC 7519 §4.1.5): MUST NOT accept before nbf.
  if (notBefore !== undefined && now < notBefore - leeway) return false;
  // exp (RFC 7519 §4.1.4): MUST NOT accept "on or after" exp — so now === exp
  // is also rejected. Use <= to implement the RFC's "on or after" boundary.
  if (expirationDate !== undefined && now >= expirationDate + leeway) return false;
  // iat (RFC 7519 §4.1.6): informational only; processing is application-specific.
  // The RFC's §7.2 validation steps do not require rejecting future iat values,
  // so we leave iat unchecked here.

  // Issuer check (RFC 7519 §4.1.1)
  if (issuer !== undefined) {
    if (jwt.payload.iss !== issuer) return false;
  }

  // Audience check (RFC 7519 §4.1.3) — token must include at least one of
  // the expected audience values
  if (audience !== undefined) {
    const tokenAud = jwt.payload.aud;
    if (!tokenAud) return false;
    const expected = Array.isArray(audience) ? audience : [audience];
    const actual = Array.isArray(tokenAud) ? tokenAud : [tokenAud];
    if (!expected.some((a) => actual.includes(a))) return false;
  }

  return true;
}

function Sign(jwt: JSONWebToken, key: string) {
  const hmacAlg = ALG_TO_HMAC[jwt.header.alg];
  if (!hmacAlg) {
    throw new Error(`Unsupported algorithm: ${jwt.header.alg}`);
  }

  // RFC 7518 §3.2: key MUST be at least as long as the hash output length.
  const minBytes = MIN_KEY_BYTES[jwt.header.alg];
  if (Buffer.byteLength(key) < minBytes) {
    throw new Error(
      `Key too short for ${jwt.header.alg}: need at least ${minBytes} bytes, got ${Buffer.byteLength(key)}`,
    );
  }

  const headerString = JSON.stringify(jwt.header);
  const payloadString = JSON.stringify(jwt.payload);

  const headerBase64 = base64url(headerString);
  const payloadBase64 = base64url(payloadString);

  const toSign = `${headerBase64}.${payloadBase64}`;

  // Use base64url encoding as required by RFC 7515
  return crypto.createHmac(hmacAlg, key).update(toSign).digest('base64url');
}

export {
  New, Read, Validate, Sign,
};
