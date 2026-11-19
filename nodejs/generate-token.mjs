#!/usr/bin/env node
/**
 * Example: generating an AdvaView launch token in Node.js.
 *
 * An AdvaView launch token is a short-lived credential that grants a named user access to a
 * specific set of studies in AdvaView, the AdvaPACS viewer. Your system builds the token, protects
 * it with the access key you were issued, and passes it to AdvaView.
 *
 * How a launch token is produced:
 *   1. Collect the inputs   - who the user is, which studies they may open, and the token lifetime.
 *   2. Build the payload    - the JSON claims AdvaView will read.
 *   3. Protect the payload  - encrypt it (JWE, recommended) or sign it (JWS) using your access key.
 *
 * Uses the `jose` library (https://github.com/panva/jose).
 *
 * Usage:
 *   npm install
 *   node generate-token.mjs --username jane.doe@example.com --suid 1.2.840.113619.2.55.3.1234 \
 *       --accessKeyId <id> --accessKeySecret <secret> --expireAfter 300
 */
import { createHash, randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';
import { CompactEncrypt, CompactSign } from 'jose';

// ---------------------------------------------------------------------------------------------
// Step 1: collect the inputs.
//
// In your own integration these values would come from your application: the signed-in user,
// the studies they are viewing, and the access key stored in your secrets manager.
// ---------------------------------------------------------------------------------------------
function readInputs() {
  const { values } = parseArgs({
    options: {
      username: { type: 'string' },
      suid: { type: 'string', multiple: true, default: [] }, // may be repeated
      patientId: { type: 'string' },
      accNum: { type: 'string', multiple: true, default: [] }, // may be repeated
      mode: { type: 'string', default: 'jwe' }, // JWE (encrypted) is the recommended default
      accessKeyId: { type: 'string' },
      accessKeySecret: { type: 'string' },
      expireAfter: { type: 'string' },
    },
  });

  if (!values.username) throw new Error('--username is required');

  const expireAfter = Number(values.expireAfter);
  if (!Number.isInteger(expireAfter) || expireAfter <= 0) {
    throw new Error('--expireAfter is required and must be a positive number of seconds');
  }

  // Studies are identified EITHER by Study Instance UID, OR by patient ID + accession number(s).
  const bySuid = values.suid.length > 0;
  const byAccession = Boolean(values.patientId) && values.accNum.length > 0;
  if (bySuid === byAccession) {
    throw new Error(
      'Provide either at least one --suid, OR --patientId with at least one --accNum (not both)',
    );
  }

  const mode = values.mode.toLowerCase();
  if (!['jwe', 'jws', 'json'].includes(mode)) throw new Error('--mode must be jwe, jws or json');
  if (mode !== 'json' && (!values.accessKeyId || !values.accessKeySecret)) {
    throw new Error('--accessKeyId and --accessKeySecret are required unless --mode is json');
  }

  return { ...values, mode, expireAfter };
}

// ---------------------------------------------------------------------------------------------
// Step 2: build the JSON payload (the token's claims).
//
//   username   - the user the token is issued to.
//   patientId  - only present when studies are identified by accession number.
//   studies    - the studies the user may open; each has a studyInstanceUid OR an accessionNumber.
//   expiresAt  - when the token stops being accepted, in seconds since the Unix epoch (UTC).
//   jti        - a unique ID for this token. Generate a new random value for every token; it lets
//                AdvaPACS reject a token that is presented more than once.
// ---------------------------------------------------------------------------------------------
function buildPayload(inputs) {
  const payload = { username: inputs.username };

  if (inputs.suid.length > 0) {
    payload.studies = inputs.suid.map((uid) => ({ studyInstanceUid: uid }));
  } else {
    payload.patientId = inputs.patientId;
    payload.studies = inputs.accNum.map((acc) => ({ accessionNumber: acc }));
  }

  payload.expiresAt = Math.floor(Date.now() / 1000) + inputs.expireAfter;
  payload.jti = randomUUID();

  return JSON.stringify(payload);
}

// ---------------------------------------------------------------------------------------------
// Step 3: protect the payload with your access key.
//
//   Key derivation: the 256-bit key is SHA-256(UTF-8 bytes of the access key secret).
//                   Use the hash, not the raw secret.
//   Key ID:         the access key ID goes in the `kid` header so AdvaPACS knows which key to use.
//   JWE (recommended): alg A256KW, enc A256GCM. The payload is encrypted, so patient
//                      identifiers (PHI) can't leak into server logs, proxies or browser
//                      history, and it can't be altered.
//   JWS:               alg HS256. Tamper-proof, but the payload is only base64url-encoded,
//                      so anyone who sees the token can read it. Use only if you can't use JWE.
// ---------------------------------------------------------------------------------------------
function deriveKey(accessKeySecret) {
  return createHash('sha256').update(accessKeySecret, 'utf8').digest();
}

async function sign(payload, accessKeyId, key) {
  return new CompactSign(new TextEncoder().encode(payload))
    .setProtectedHeader({ alg: 'HS256', kid: accessKeyId })
    .sign(key);
}

async function encrypt(payload, accessKeyId, key) {
  return new CompactEncrypt(new TextEncoder().encode(payload))
    .setProtectedHeader({ alg: 'A256KW', enc: 'A256GCM', kid: accessKeyId })
    .encrypt(key);
}

// ---------------------------------------------------------------------------------------------

async function main() {
  const inputs = readInputs();
  const payload = buildPayload(inputs);

  if (inputs.mode === 'json') {
    // Debug output only: this payload is NOT protected and must not be used as a token.
    console.log(payload);
    return;
  }

  const key = deriveKey(inputs.accessKeySecret);
  const token =
    inputs.mode === 'jwe'
      ? await encrypt(payload, inputs.accessKeyId, key) // recommended
      : await sign(payload, inputs.accessKeyId, key);

  console.log(token);
}

main().catch((err) => {
  console.error(`Error: ${err.message}

Usage:
  node generate-token.mjs \\
    --username <username> \\
    --expireAfter <seconds> \\
    ( --suid <suid> [--suid <suid> ...] | --patientId <id> --accNum <acc> [--accNum <acc> ...] ) \\
    --accessKeyId <id> \\          # required unless --mode json
    --accessKeySecret <secret> \\  # required unless --mode json
    [--mode jwe|jws|json]          # default: jwe`);
  process.exit(1);
});
