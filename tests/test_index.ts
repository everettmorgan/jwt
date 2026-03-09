import { expect } from "chai";
import * as JWT from "../src/index";

// 64-byte key satisfies the minimum for HS256 (32 B), HS384 (48 B), and HS512 (64 B)
// per RFC 7518 §3.2.
const key = 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP';

// Helper: current time in seconds (JWT NumericDate)
const nowSec = () => Math.floor(Date.now() / 1000);

const jwt = JWT.New({
  header: { alg: "HS256" },
  payload: { aud: "everett", mykey: "test" },
  key: key
});

describe("JWT", function () {
  // ── Creation ──────────────────────────────────────────────────────────────

  it("can create a new JWT", function () {
    expect(jwt.header.alg).to.equal("HS256");
    expect(jwt.payload.aud).to.equal("everett");
    expect(jwt.payload.mykey).to.equal("test");
    expect(jwt.signature).to.not.be.null;
    expect(jwt.signature).to.not.be.undefined;
  });

  it("produces distinct signatures for HS384 and HS512", function () {
    const jwt384 = JWT.New({ header: { alg: "HS384" }, payload: { sub: "u1" }, key });
    const jwt512 = JWT.New({ header: { alg: "HS512" }, payload: { sub: "u1" }, key });
    expect(jwt384.signature).to.not.equal(jwt.signature);
    expect(jwt512.signature).to.not.equal(jwt384.signature);
  });

  // ── Read / signature verification ─────────────────────────────────────────

  it("can generate and validate a signature", function () {
    const [err, compare] = JWT.Read(jwt.toString(), key);
    expect(err).to.be.false;
    expect(compare).to.not.be.null;
    expect((compare as any).signature).to.equal(jwt.signature);
  });

  it("Read returns error for wrong key", function () {
    const wrongKey = 'QQQQRRRRSSSSTTTTQQQQRRRRSSSSTTTT';  // 32 bytes, different value
    const [err, result] = JWT.Read(jwt.toString(), wrongKey);
    expect(err).to.be.true;
    expect(result).to.be.null;
  });

  it("Read returns error when a JWT segment is missing", function () {
    const [headerB64, payloadB64] = jwt.toString().split('.');
    const [err, result] = JWT.Read(`${headerB64}.${payloadB64}`, key);
    expect(err).to.be.true;
    expect(result).to.be.null;
  });

  it("Read returns error when header is tampered", function () {
    const parts = jwt.toString().split('.');
    const tamperedHeader = Buffer.from(JSON.stringify({ alg: "HS512" })).toString('base64url');
    const [err, result] = JWT.Read(`${tamperedHeader}.${parts[1]}.${parts[2]}`, key);
    expect(err).to.be.true;
    expect(result).to.be.null;
  });

  it("Read returns error when payload is tampered", function () {
    const parts = jwt.toString().split('.');
    const tamperedPayload = Buffer.from(JSON.stringify({ aud: "attacker" })).toString('base64url');
    const [err, result] = JWT.Read(`${parts[0]}.${tamperedPayload}.${parts[2]}`, key);
    expect(err).to.be.true;
    expect(result).to.be.null;
  });

  it("Read returns error for invalid base64 in header", function () {
    const [err, result] = JWT.Read("!!!.e30.sig", key);
    expect(err).to.be.true;
    expect(result).to.be.null;
  });

  it("Read returns error for invalid JSON in payload", function () {
    const badPayload = Buffer.from("not-json").toString('base64url');
    const parts = jwt.toString().split('.');
    const [err, result] = JWT.Read(`${parts[0]}.${badPayload}.${parts[2]}`, key);
    expect(err).to.be.true;
    expect(result).to.be.null;
  });

  it("Read returns error for a token with an unsupported algorithm", function () {
    const fakeHeader = Buffer.from(JSON.stringify({ alg: "RS256" })).toString('base64url');
    const fakePayload = Buffer.from(JSON.stringify({ sub: "x" })).toString('base64url');
    const [err, result] = JWT.Read(`${fakeHeader}.${fakePayload}.fakesig`, key);
    expect(err).to.be.true;
    expect(result).to.be.null;
  });

  // ── Validate ──────────────────────────────────────────────────────────────

  it("can validate a jwt", function () {
    const a = JWT.Validate(jwt, key);
    jwt.payload.aud = 'hehehe';
    const b = JWT.Validate(jwt, key);

    expect(a).to.be.true;
    expect(b).to.be.false;
  });

  it("rejects a token with an expired exp", function () {
    const expired = JWT.New({
      header: { alg: "HS256" },
      payload: { exp: nowSec() - 60 },
      key
    });
    expect(JWT.Validate(expired, key)).to.be.false;
  });

  it("accepts a token whose exp is in the future", function () {
    const valid = JWT.New({
      header: { alg: "HS256" },
      payload: { exp: nowSec() + 3600 },
      key
    });
    expect(JWT.Validate(valid, key)).to.be.true;
  });

  it("rejects a token whose nbf is in the future", function () {
    const notYet = JWT.New({
      header: { alg: "HS256" },
      payload: { nbf: nowSec() + 3600 },
      key
    });
    expect(JWT.Validate(notYet, key)).to.be.false;
  });

  it("accepts a token whose nbf is in the past", function () {
    const ready = JWT.New({
      header: { alg: "HS256" },
      payload: { nbf: nowSec() - 60 },
      key
    });
    expect(JWT.Validate(ready, key)).to.be.true;
  });

  it("accepts a token whose iat is in the past", function () {
    const past = JWT.New({
      header: { alg: "HS256" },
      payload: { iat: nowSec() - 60 },
      key
    });
    expect(JWT.Validate(past, key)).to.be.true;
  });

  it("rejects a token signed with the wrong key", function () {
    const otherKey = 'QQQQRRRRSSSSTTTTQQQQRRRRSSSSTTTT';  // 32 bytes, different value
    const other = JWT.New({ header: { alg: "HS256" }, payload: { sub: "x" }, key: otherKey });
    expect(JWT.Validate(other, key)).to.be.false;
  });

  // ── Audience validation ───────────────────────────────────────────────────

  it("accepts a token whose aud matches the expected audience", function () {
    const t = JWT.New({ header: { alg: "HS256" }, payload: { aud: "api" }, key });
    expect(JWT.Validate(t, key, { audience: "api" })).to.be.true;
  });

  it("rejects a token whose aud does not match the expected audience", function () {
    const t = JWT.New({ header: { alg: "HS256" }, payload: { aud: "api" }, key });
    expect(JWT.Validate(t, key, { audience: "other" })).to.be.false;
  });

  it("rejects a token with no aud when audience is required", function () {
    const t = JWT.New({ header: { alg: "HS256" }, payload: { sub: "u1" }, key });
    expect(JWT.Validate(t, key, { audience: "api" })).to.be.false;
  });

  it("accepts a token when aud is an array containing the expected value", function () {
    const t = JWT.New({ header: { alg: "HS256" }, payload: { aud: ["api", "admin"] }, key });
    expect(JWT.Validate(t, key, { audience: "admin" })).to.be.true;
  });

  it("accepts a token when expected audience array overlaps token aud", function () {
    const t = JWT.New({ header: { alg: "HS256" }, payload: { aud: "api" }, key });
    expect(JWT.Validate(t, key, { audience: ["other", "api"] })).to.be.true;
  });

  // ── Issuer validation ─────────────────────────────────────────────────────

  it("accepts a token whose iss matches the expected issuer", function () {
    const t = JWT.New({ header: { alg: "HS256" }, payload: { iss: "auth.example.com" }, key });
    expect(JWT.Validate(t, key, { issuer: "auth.example.com" })).to.be.true;
  });

  it("rejects a token whose iss does not match the expected issuer", function () {
    const t = JWT.New({ header: { alg: "HS256" }, payload: { iss: "evil.example.com" }, key });
    expect(JWT.Validate(t, key, { issuer: "auth.example.com" })).to.be.false;
  });

  it("rejects a token with no iss when an issuer is required", function () {
    const t = JWT.New({ header: { alg: "HS256" }, payload: { sub: "u1" }, key });
    expect(JWT.Validate(t, key, { issuer: "auth.example.com" })).to.be.false;
  });

  // ── Clock skew leeway ─────────────────────────────────────────────────────

  it("accepts a just-expired token when leeway covers the difference", function () {
    const t = JWT.New({
      header: { alg: "HS256" },
      payload: { exp: nowSec() - 10 },  // expired 10 seconds ago
      key
    });
    expect(JWT.Validate(t, key, { leeway: 30 })).to.be.true;
  });

  it("rejects a token expired beyond the leeway window", function () {
    const t = JWT.New({
      header: { alg: "HS256" },
      payload: { exp: nowSec() - 60 },  // expired 60 seconds ago
      key
    });
    expect(JWT.Validate(t, key, { leeway: 10 })).to.be.false;
  });

  it("accepts a slightly-future nbf when leeway covers the difference", function () {
    const t = JWT.New({
      header: { alg: "HS256" },
      payload: { nbf: nowSec() + 10 },  // valid in 10 seconds
      key
    });
    expect(JWT.Validate(t, key, { leeway: 30 })).to.be.true;
  });

  // ── Algorithm guard ───────────────────────────────────────────────────────

  it("throws when creating a JWT with an unsupported algorithm", function () {
    expect(() => JWT.New({
      header: { alg: "RS256" as any },
      payload: {},
      key
    })).to.throw(/Unsupported algorithm/);
  });

  it("throws for alg 'none'", function () {
    expect(() => JWT.New({
      header: { alg: "none" as any },
      payload: {},
      key
    })).to.throw(/Unsupported algorithm/);
  });

  // ── RFC 7519 §4.1.4: exp "on or after" boundary ───────────────────────────

  it("rejects a token whose exp equals the current time (RFC 7519 §4.1.4 on-or-after)", function () {
    // RFC §4.1.4: MUST NOT accept "on or after" exp — exp === now must be rejected.
    const t = JWT.New({
      header: { alg: "HS256" },
      payload: { exp: nowSec() },
      key
    });
    expect(JWT.Validate(t, key)).to.be.false;
  });

  // ── RFC 7519 §4.1.6: iat is informational ─────────────────────────────────

  it("accepts a token whose iat is in the future (RFC 7519 §4.1.6 iat is informational)", function () {
    // RFC §4.1.6: iat processing is application-specific; the RFC's §7.2 validation
    // steps do not require rejecting future iat values.
    const t = JWT.New({
      header: { alg: "HS256" },
      payload: { iat: nowSec() + 3600 },
      key
    });
    expect(JWT.Validate(t, key)).to.be.true;
  });

  // ── RFC 7515 §6.1: compact serialization requires all three parts ──────────

  it("toString() throws for an unsigned JWT (RFC 7515 §6.1)", function () {
    const unsigned = JWT.New({ header: { alg: "HS256" }, payload: { sub: "x" } });
    expect(() => unsigned.toString()).to.throw(/Cannot serialize an unsigned JWT/);
  });

  // ── RFC 7518 §3.2: minimum HMAC key length ────────────────────────────────

  it("throws when HS256 key is shorter than 32 bytes (RFC 7518 §3.2)", function () {
    expect(() => JWT.New({ header: { alg: "HS256" }, payload: {}, key: "short" }))
      .to.throw(/Key too short/);
  });

  it("throws when HS384 key is shorter than 48 bytes (RFC 7518 §3.2)", function () {
    const key32 = 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH';  // 32 bytes — not enough for HS384
    expect(() => JWT.New({ header: { alg: "HS384" }, payload: {}, key: key32 }))
      .to.throw(/Key too short/);
  });

  it("throws when HS512 key is shorter than 64 bytes (RFC 7518 §3.2)", function () {
    const key32 = 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH';  // 32 bytes — not enough for HS512
    expect(() => JWT.New({ header: { alg: "HS512" }, payload: {}, key: key32 }))
      .to.throw(/Key too short/);
  });

  // ── RFC 7519 §10.1: algorithm pinning in Read() ────────────────────────────

  it("Read() accepts a token when algorithm pin matches the header alg", function () {
    const t = JWT.New({ header: { alg: "HS256" }, payload: { sub: "pin-test" }, key });
    const [err, result] = JWT.Read(t.toString(), key, "HS256");
    expect(err).to.be.false;
    expect(result).to.not.be.null;
  });

  it("Read() rejects a token when algorithm does not match the pin (RFC 7519 §10.1)", function () {
    // Token was signed with HS256; pinning HS512 must cause rejection.
    const t = JWT.New({ header: { alg: "HS256" }, payload: { sub: "pin-test" }, key });
    const [err, result] = JWT.Read(t.toString(), key, "HS512");
    expect(err).to.be.true;
    expect(result).to.be.null;
  });

  // ── RFC 7515 §4.1.11: crit header must cause rejection ────────────────────

  it("Read() rejects a token with a non-empty crit header (RFC 7515 §4.1.11)", function () {
    // Craft a token header that includes the crit extension list.
    // This library implements no extensions, so any crit claim must be rejected.
    const critHeader = Buffer
      .from(JSON.stringify({ alg: "HS256", crit: ["extension1"] }))
      .toString('base64url');
    const parts = jwt.toString().split('.');
    const [err, result] = JWT.Read(`${critHeader}.${parts[1]}.${parts[2]}`, key);
    expect(err).to.be.true;
    expect(result).to.be.null;
  });
});
