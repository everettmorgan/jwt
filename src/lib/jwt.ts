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

function Read(jwtstr: string, key: string): [boolean, JSONWebToken | null] {
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

  let jwt: JSONWebToken;
  try {
    jwt = New({ header, payload, key });
  } catch {
    // New() → Sign() throws for unsupported algorithms
    return [true, null];
  }

  if (jwt.signature !== signature) return [true, null];

  return [false, jwt];
}

function Validate(jwt: JSONWebToken, key: string, opts: ValidateOptions = {}): boolean {
  const { audience, issuer, leeway = 0 } = opts;
  const expirationDate = jwt.payload.exp;
  const notBefore = jwt.payload.nbf;
  const issuedAt = jwt.payload.iat;
  const { signature } = jwt;

  // JWT NumericDate values are seconds since epoch (RFC 7519 §2)
  const now = Math.floor(Date.now() / 1000);

  // eslint-disable-next-line no-use-before-define
  const check = Sign(jwt, key);

  // Signature must be present and match
  if (!signature) return false;
  if (check !== signature) return false;

  // Time claims — leeway accounts for clock skew in distributed systems
  if (issuedAt && issuedAt > now + leeway) return false;
  if (notBefore && now < notBefore - leeway) return false;
  if (expirationDate && expirationDate + leeway < now) return false;

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
