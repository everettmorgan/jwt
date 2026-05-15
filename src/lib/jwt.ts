import { createHmac, timingSafeEqual } from 'node:crypto';
import type { BinaryLike, KeyObject } from 'node:crypto';

export type JwtAlgorithm = 'HS256' | 'HS384' | 'HS512';

export type JwtSecret = BinaryLike | KeyObject;

export interface JwtHeader {
  alg: JwtAlgorithm;
  typ?: string;
  cty?: string;
  kid?: string;
  [parameter: string]: unknown;
}

export interface JwtPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [claim: string]: unknown;
}

export interface DecodedJwt {
  header: JwtHeader;
  payload: JwtPayload;
  signature: string;
  signingInput: string;
  token: string;
}

export interface SignOptions {
  algorithm?: JwtAlgorithm;
  header?: Record<string, unknown>;
}

export interface VerifyOptions {
  algorithms?: readonly JwtAlgorithm[];
  clockTimestamp?: number;
  clockTolerance?: number;
}

export type JwtErrorCode =
  | 'malformed_token'
  | 'invalid_base64url'
  | 'invalid_json'
  | 'unsupported_algorithm'
  | 'bad_signature'
  | 'expired'
  | 'not_before'
  | 'issued_at_future'
  | 'invalid_claim'
  | 'invalid_option';

export class JwtError extends Error {
  readonly code: JwtErrorCode;

  constructor(code: JwtErrorCode, message: string) {
    super(message);
    this.name = 'JwtError';
    this.code = code;
  }
}

const hmacAlgorithms: Record<JwtAlgorithm, string> = {
  HS256: 'sha256',
  HS384: 'sha384',
  HS512: 'sha512',
};

const base64urlPattern = /^[A-Za-z0-9_-]+$/;

export function sign(payload: JwtPayload, secret: JwtSecret, options: SignOptions = {}): string {
  const algorithm = options.algorithm ?? 'HS256';
  assertSupportedAlgorithm(algorithm);

  const header: JwtHeader = {
    typ: 'JWT',
    ...options.header,
    alg: algorithm,
  };

  const encodedHeader = encodeJson(header);
  const encodedPayload = encodeJson(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = signInput(signingInput, algorithm, secret);

  return `${signingInput}.${signature}`;
}

export function decode(token: string): DecodedJwt {
  const { headerSegment, payloadSegment, signature } = parseTokenSegments(token);
  const header = parseJsonSegment(headerSegment, 'header');
  const payload = parseJsonSegment(payloadSegment, 'payload');

  if (!isRecord(header)) {
    throw new JwtError('malformed_token', 'JWT header must be a JSON object');
  }

  if (!isRecord(payload)) {
    throw new JwtError('malformed_token', 'JWT payload must be a JSON object');
  }

  if (!isJwtAlgorithm(header.alg)) {
    throw new JwtError('unsupported_algorithm', 'JWT algorithm is not supported');
  }

  const signingInput = `${headerSegment}.${payloadSegment}`;

  return {
    header: header as unknown as JwtHeader,
    payload: payload as JwtPayload,
    signature,
    signingInput,
    token,
  };
}

export function verify(token: string, secret: JwtSecret, options: VerifyOptions = {}): DecodedJwt {
  const decoded = decode(token);
  const algorithms = options.algorithms ?? Object.keys(hmacAlgorithms);

  if (!algorithms.includes(decoded.header.alg)) {
    throw new JwtError('unsupported_algorithm', `JWT algorithm ${decoded.header.alg} is not allowed`);
  }

  const expected = signInput(decoded.signingInput, decoded.header.alg, secret);

  if (!constantTimeEqual(expected, decoded.signature)) {
    throw new JwtError('bad_signature', 'JWT signature is invalid');
  }

  validateClaims(decoded.payload, options);

  return decoded;
}

function parseTokenSegments(token: string): {
  headerSegment: string;
  payloadSegment: string;
  signature: string;
} {
  const segments = token.split('.');

  if (segments.length !== 3) {
    throw new JwtError('malformed_token', 'JWT must contain three dot-separated segments');
  }

  const [headerSegment, payloadSegment, signature] = segments;

  if (!headerSegment || !payloadSegment || !signature) {
    throw new JwtError('malformed_token', 'JWT segments must not be empty');
  }

  assertBase64url(headerSegment, 'header');
  assertBase64url(payloadSegment, 'payload');
  assertBase64url(signature, 'signature');

  return { headerSegment, payloadSegment, signature };
}

function assertBase64url(value: string, segmentName: string): void {
  if (!base64urlPattern.test(value) || value.length % 4 === 1) {
    throw new JwtError('invalid_base64url', `JWT ${segmentName} segment is not valid base64url`);
  }
}

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function parseJsonSegment(segment: string, segmentName: string): unknown {
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch {
    throw new JwtError('invalid_json', `JWT ${segmentName} segment is not valid JSON`);
  }
}

function signInput(signingInput: string, algorithm: JwtAlgorithm, secret: JwtSecret): string {
  return createHmac(hmacAlgorithms[algorithm], secret).update(signingInput).digest('base64url');
}

function constantTimeEqual(expected: string, actual: string): boolean {
  const expectedBuffer = Buffer.from(expected);
  const actualBuffer = Buffer.from(actual);

  return expectedBuffer.length === actualBuffer.length && timingSafeEqual(expectedBuffer, actualBuffer);
}

function validateClaims(payload: JwtPayload, options: VerifyOptions): void {
  const clockTimestamp = options.clockTimestamp ?? Math.floor(Date.now() / 1000);
  const clockTolerance = options.clockTolerance ?? 0;

  assertNonNegativeNumber(clockTimestamp, 'clockTimestamp');
  assertNonNegativeNumber(clockTolerance, 'clockTolerance');

  const exp = getNumericDate(payload, 'exp');
  const nbf = getNumericDate(payload, 'nbf');
  const iat = getNumericDate(payload, 'iat');

  if (exp !== undefined && clockTimestamp - clockTolerance >= exp) {
    throw new JwtError('expired', 'JWT has expired');
  }

  if (nbf !== undefined && clockTimestamp + clockTolerance < nbf) {
    throw new JwtError('not_before', 'JWT is not active yet');
  }

  if (iat !== undefined && clockTimestamp + clockTolerance < iat) {
    throw new JwtError('issued_at_future', 'JWT issued-at claim is in the future');
  }
}

function getNumericDate(payload: JwtPayload, claim: 'exp' | 'nbf' | 'iat'): number | undefined {
  const value = payload[claim];

  if (value === undefined) {
    return undefined;
  }

  if (!Number.isFinite(value)) {
    throw new JwtError('invalid_claim', `JWT ${claim} claim must be a finite NumericDate`);
  }

  return value;
}

function assertNonNegativeNumber(value: number, optionName: string): void {
  if (!Number.isFinite(value) || value < 0) {
    throw new JwtError('invalid_option', `${optionName} must be a non-negative finite number`);
  }
}

function assertSupportedAlgorithm(algorithm: JwtAlgorithm): void {
  if (!isJwtAlgorithm(algorithm)) {
    throw new JwtError('unsupported_algorithm', 'JWT algorithm is not supported');
  }
}

function isJwtAlgorithm(value: unknown): value is JwtAlgorithm {
  return typeof value === 'string' && value in hmacAlgorithms;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
