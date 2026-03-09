import * as crypto from 'crypto';
import base64url from 'base64url';
// eslint-disable-next-line import/no-unresolved, import/extensions
import { JWTRegisteredClaimNames, JWSRegisteredHeaderParameters } from './base';

interface JSONWebTokenConstructor {
  key?: string;
  header: JWSRegisteredHeaderParameters;
  payload: JWTRegisteredClaimNames;
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

  const headerString = base64url.decode(headerBase64);
  const payloadString = base64url.decode(payloadBase64);

  const header = JSON.parse(headerString);
  const payload = JSON.parse(payloadString);

  const jwt = New({ header, payload, key });

  if (jwt.signature !== signature) return [true, null];

  return [false, jwt];
}

function Validate(jwt: JSONWebToken, key: string): boolean {
  const expirationDate = jwt.payload.exp;
  const notBefore = jwt.payload.nbf;
  const issuedAt = jwt.payload.iat;
  const { signature } = jwt;
  // JWT NumericDate values are seconds since epoch (RFC 7519 §2)
  const now = Math.floor(Date.now() / 1000);
  // eslint-disable-next-line no-use-before-define
  const check = Sign(jwt, key);

  if (issuedAt && issuedAt > now) return false;
  if (notBefore && now < notBefore) return false;
  if (expirationDate && expirationDate < now) return false;
  if (!signature) return false;
  if (check !== signature) return false;

  return true;
}

const SUPPORTED_ALGORITHMS = ['sha256', 'sha384', 'sha512'];

function Sign(jwt: JSONWebToken, key: string) {
  if (!SUPPORTED_ALGORITHMS.includes(jwt.header.alg)) {
    throw new Error(`Unsupported algorithm: ${jwt.header.alg}`);
  }

  const headerString = JSON.stringify(jwt.header);
  const payloadString = JSON.stringify(jwt.payload);

  const headerBase64 = base64url(headerString);
  const payloadBase64 = base64url(payloadString);

  const toSign = `${headerBase64}.${payloadBase64}`;

  // Use base64url encoding as required by RFC 7515
  return crypto.createHmac(jwt.header.alg, key).update(toSign).digest('base64url');
}

export {
  New, Read, Validate, Sign,
};
