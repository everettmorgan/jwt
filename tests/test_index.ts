import { expect } from "chai";
import * as JWT from "../src/index";

const key = '349jfirfjeroigjerg40g9j';

// Helper: current time in seconds (JWT NumericDate)
const nowSec = () => Math.floor(Date.now() / 1000);

const jwt = JWT.New({
  header: { alg: "sha256" },
  payload: { aud: "everett", mykey: "test" },
  key: key
});

describe("JWT", function () {
  // ── Creation ──────────────────────────────────────────────────────────────

  it("can create a new JWT", function () {
    expect(jwt.header.alg).to.equal("sha256");
    expect(jwt.payload.aud).to.equal("everett");
    expect(jwt.payload.mykey).to.equal("test");
    expect(jwt.signature).to.not.be.null;
    expect(jwt.signature).to.not.be.undefined;
  });

  it("produces different signatures for sha384 and sha512", function () {
    const jwt384 = JWT.New({ header: { alg: "sha384" }, payload: { sub: "u1" }, key });
    const jwt512 = JWT.New({ header: { alg: "sha512" }, payload: { sub: "u1" }, key });
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
    const [err, result] = JWT.Read(jwt.toString(), "wrong-key");
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
    // Replace header with a re-encoded version that has a different alg
    const tamperedHeader = Buffer.from(JSON.stringify({ alg: "sha512" })).toString('base64url');
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
      header: { alg: "sha256" },
      payload: { exp: nowSec() - 60 },   // 60 seconds in the past
      key
    });
    expect(JWT.Validate(expired, key)).to.be.false;
  });

  it("accepts a token whose exp is in the future", function () {
    const valid = JWT.New({
      header: { alg: "sha256" },
      payload: { exp: nowSec() + 3600 },  // 1 hour ahead
      key
    });
    expect(JWT.Validate(valid, key)).to.be.true;
  });

  it("rejects a token whose nbf is in the future", function () {
    const notYet = JWT.New({
      header: { alg: "sha256" },
      payload: { nbf: nowSec() + 3600 },  // valid 1 hour from now
      key
    });
    expect(JWT.Validate(notYet, key)).to.be.false;
  });

  it("accepts a token whose nbf is in the past", function () {
    const ready = JWT.New({
      header: { alg: "sha256" },
      payload: { nbf: nowSec() - 60 },
      key
    });
    expect(JWT.Validate(ready, key)).to.be.true;
  });

  it("rejects a token whose iat is in the future", function () {
    const future = JWT.New({
      header: { alg: "sha256" },
      payload: { iat: nowSec() + 3600 },
      key
    });
    expect(JWT.Validate(future, key)).to.be.false;
  });

  it("accepts a token whose iat is in the past", function () {
    const past = JWT.New({
      header: { alg: "sha256" },
      payload: { iat: nowSec() - 60 },
      key
    });
    expect(JWT.Validate(past, key)).to.be.true;
  });

  it("rejects a token signed with the wrong key", function () {
    const other = JWT.New({ header: { alg: "sha256" }, payload: { sub: "x" }, key: "other-key" });
    expect(JWT.Validate(other, key)).to.be.false;
  });

  // ── Algorithm guard ───────────────────────────────────────────────────────

  it("throws when creating a JWT with an unsupported algorithm", function () {
    expect(() => JWT.New({
      header: { alg: "rs256" as any },
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
});
