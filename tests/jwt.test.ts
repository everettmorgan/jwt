import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import {
  JwtError,
  decode,
  sign,
  verify,
} from '../src/index';
import type { JwtAlgorithm, JwtErrorCode, JwtPayload } from '../src/index';

const secret = 'test-secret';
const now = 1_700_000_000;

describe('sign', () => {
  test('creates a standards-compatible HMAC JWT', () => {
    const token = sign({ aud: 'everett', custom: 'value' }, secret);
    const segments = token.split('.');

    assert.equal(segments.length, 3);
    assert.doesNotMatch(token, /=/);

    const decoded = decode(token);

    assert.deepEqual(decoded.header, { alg: 'HS256', typ: 'JWT' });
    assert.deepEqual(decoded.payload, { aud: 'everett', custom: 'value' });
    assert.equal(decoded.signature, segments[2]);
    assert.equal(decoded.signingInput, `${segments[0]}.${segments[1]}`);
  });

  test('supports all implemented HMAC algorithms', () => {
    const algorithms: JwtAlgorithm[] = ['HS256', 'HS384', 'HS512'];

    for (const algorithm of algorithms) {
      const token = sign({ sub: algorithm }, secret, { algorithm });

      assert.equal(verify(token, secret).header.alg, algorithm);
    }
  });

  test('rejects unsupported algorithms from JavaScript callers', () => {
    assertJwtError(
      () => sign({ sub: '123' }, secret, { algorithm: 'RS256' as JwtAlgorithm }),
      'unsupported_algorithm',
    );
  });

  test('merges additional header parameters without letting them override the algorithm', () => {
    const token = sign({ sub: '123' }, secret, {
      algorithm: 'HS384',
      header: { alg: 'HS512', kid: 'key-1' },
    });

    assert.deepEqual(decode(token).header, {
      alg: 'HS384',
      kid: 'key-1',
      typ: 'JWT',
    });
  });
});

describe('decode', () => {
  test('parses a token without verifying the signature', () => {
    const token = sign({ sub: '123' }, secret);
    const decoded = decode(token);

    assert.equal(decoded.header.alg, 'HS256');
    assert.deepEqual(decoded.payload, { sub: '123' });
    assert.equal(decoded.token, token);
  });

  test('rejects malformed tokens', () => {
    const cases = [
      'header.payload',
      'header.payload.signature.extra',
      `${encodeJson({ alg: 'HS256' })}.${encodeJson({ sub: '123' })}.`,
      `${encodeJson({ alg: 'HS256' })}..${encodeJson('signature')}`,
    ];

    for (const token of cases) {
      assertJwtError(() => decode(token), 'malformed_token');
    }
  });

  test('rejects invalid base64url segments', () => {
    assertJwtError(() => decode('@@@.payload.signature'), 'invalid_base64url');
    assertJwtError(() => decode('a.payload.signature'), 'invalid_base64url');
  });

  test('rejects invalid JSON segments', () => {
    const invalidHeader = `${encodeText('not-json')}.${encodeJson({ sub: '123' })}.${encodeText('signature')}`;
    const invalidPayload = `${encodeJson({ alg: 'HS256' })}.${encodeText('not-json')}.${encodeText('signature')}`;

    assertJwtError(() => decode(invalidHeader), 'invalid_json');
    assertJwtError(() => decode(invalidPayload), 'invalid_json');
  });

  test('rejects unsupported algorithms', () => {
    const token = `${encodeJson({ alg: 'RS256' })}.${encodeJson({ sub: '123' })}.${encodeText('signature')}`;

    assertJwtError(() => decode(token), 'unsupported_algorithm');
  });

  test('rejects non-object header and payload JSON', () => {
    const stringHeader = `${encodeJson('header')}.${encodeJson({ sub: '123' })}.${encodeText('signature')}`;
    const arrayPayload = `${encodeJson({ alg: 'HS256' })}.${encodeJson(['claim'])}.${encodeText('signature')}`;

    assertJwtError(() => decode(stringHeader), 'malformed_token');
    assertJwtError(() => decode(arrayPayload), 'malformed_token');
  });
});

describe('verify', () => {
  test('returns the decoded token for a valid signature', () => {
    const payload = { aud: ['app', 'api'], exp: now + 60, iat: now };
    const token = sign(payload, secret);
    const decoded = verify(token, secret, { clockTimestamp: now });

    assert.deepEqual(decoded.payload, payload);
  });

  test('rejects a tampered payload', () => {
    const token = sign({ sub: '123' }, secret);
    const [header, , signature] = splitToken(token);
    const tampered = `${header}.${encodeJson({ sub: '456' })}.${signature}`;

    assertJwtError(() => verify(tampered, secret), 'bad_signature');
  });

  test('rejects a tampered header', () => {
    const token = sign({ sub: '123' }, secret);
    const [, payload, signature] = splitToken(token);
    const tampered = `${encodeJson({ alg: 'HS512', typ: 'JWT' })}.${payload}.${signature}`;

    assertJwtError(() => verify(tampered, secret), 'bad_signature');
  });

  test('rejects a tampered signature', () => {
    const token = sign({ sub: '123' }, secret);
    const [header, payload, signature] = splitToken(token);
    const tampered = `${header}.${payload}.${flipLastBase64urlChar(signature)}`;

    assertJwtError(() => verify(tampered, secret), 'bad_signature');
  });

  test('enforces allowed algorithms', () => {
    const token = sign({ sub: '123' }, secret, { algorithm: 'HS512' });

    assertJwtError(() => verify(token, secret, { algorithms: ['HS256'] }), 'unsupported_algorithm');
  });

  test('enforces expiration using NumericDate seconds', () => {
    const valid = sign({ exp: now + 1 }, secret);
    const expired = sign({ exp: now }, secret);

    assert.equal(verify(valid, secret, { clockTimestamp: now }).payload.exp, now + 1);
    assertJwtError(() => verify(expired, secret, { clockTimestamp: now }), 'expired');
  });

  test('honors expiration clock tolerance', () => {
    const token = sign({ exp: now - 5 }, secret);

    assert.equal(verify(token, secret, { clockTimestamp: now, clockTolerance: 10 }).payload.exp, now - 5);
  });

  test('enforces not-before claims', () => {
    const token = sign({ nbf: now + 1 }, secret);

    assertJwtError(() => verify(token, secret, { clockTimestamp: now }), 'not_before');
    assert.equal(verify(token, secret, { clockTimestamp: now, clockTolerance: 1 }).payload.nbf, now + 1);
  });

  test('enforces issued-at claims', () => {
    const token = sign({ iat: now + 1 }, secret);

    assertJwtError(() => verify(token, secret, { clockTimestamp: now }), 'issued_at_future');
    assert.equal(verify(token, secret, { clockTimestamp: now, clockTolerance: 1 }).payload.iat, now + 1);
  });

  test('rejects invalid NumericDate claims', () => {
    const token = sign({ exp: 'soon' } as unknown as JwtPayload, secret);

    assertJwtError(() => verify(token, secret, { clockTimestamp: now }), 'invalid_claim');
  });

  test('rejects invalid clock options', () => {
    const token = sign({ sub: '123' }, secret);

    assertJwtError(() => verify(token, secret, { clockTimestamp: -1 }), 'invalid_option');
    assertJwtError(() => verify(token, secret, { clockTimestamp: now, clockTolerance: Number.NaN }), 'invalid_option');
  });
});

function assertJwtError(fn: () => unknown, code: JwtErrorCode): void {
  assert.throws(
    fn,
    (error: unknown) => {
      if (!(error instanceof JwtError)) {
        return false;
      }

      return error.code === code;
    },
  );
}

function encodeJson(value: unknown): string {
  return encodeText(JSON.stringify(value));
}

function encodeText(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64url');
}

function flipLastBase64urlChar(value: string): string {
  const replacement = value.endsWith('A') ? 'B' : 'A';

  return `${value.slice(0, -1)}${replacement}`;
}

function splitToken(token: string): [string, string, string] {
  const segments = token.split('.');

  assert.equal(segments.length, 3);

  return segments as [string, string, string];
}
