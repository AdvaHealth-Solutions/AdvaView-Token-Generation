#!/usr/bin/env python3
"""
Example: generating an AdvaView launch token in Python.

An AdvaView launch token is a short-lived credential that grants a named user access to a specific
set of studies in AdvaView, the AdvaPACS viewer. Your system builds the token, protects it with the
access key you were issued, and passes it to AdvaView.

How a launch token is produced:
  1. Collect the inputs   - who the user is, which studies they may open, and the token lifetime.
  2. Build the payload    - the JSON claims AdvaView will read.
  3. Protect the payload  - encrypt it (JWE, recommended) or sign it (JWS) using your access key.

Uses the `jwcrypto` library (https://github.com/latchset/jwcrypto).

Usage:
  pip install -r requirements.txt
  python generate_token.py --username jane.doe@example.com --suid 1.2.840.113619.2.55.3.1234 \\
      --accessKeyId <id> --accessKeySecret <secret> --expireAfter 300
"""
import argparse
import hashlib
import json
import sys
import time
import uuid

from jwcrypto import jwe, jwk, jws
from jwcrypto.common import base64url_encode


# ------------------------------------------------------------------------------------------------
# Step 1: collect the inputs.
#
# In your own integration these values would come from your application: the signed-in user, the
# studies they are viewing, and the access key stored in your secrets manager.
# ------------------------------------------------------------------------------------------------
def read_inputs() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate an AdvaView launch token.")
    parser.add_argument("--username", required=True)
    parser.add_argument("--suid", action="append", default=[], help="may be repeated")
    parser.add_argument("--patientId")
    parser.add_argument("--accNum", action="append", default=[], help="may be repeated")
    parser.add_argument(
        "--mode",
        default="jwe",  # JWE (encrypted) is the recommended default
        type=str.lower,
        choices=["jwe", "jws", "json"],
    )
    parser.add_argument("--accessKeyId", help="required unless --mode json")
    parser.add_argument("--accessKeySecret", help="required unless --mode json")
    parser.add_argument("--expireAfter", required=True, type=int, help="token lifetime in seconds")
    args = parser.parse_args()

    if args.expireAfter <= 0:
        parser.error("--expireAfter must be a positive number of seconds")

    # Studies are identified EITHER by Study Instance UID, OR by patient ID + accession number(s).
    by_suid = len(args.suid) > 0
    by_accession = bool(args.patientId) and len(args.accNum) > 0
    if by_suid == by_accession:
        parser.error(
            "provide either at least one --suid, OR --patientId with at least one --accNum (not both)"
        )

    if args.mode != "json" and not (args.accessKeyId and args.accessKeySecret):
        parser.error("--accessKeyId and --accessKeySecret are required unless --mode is json")

    return args


# ------------------------------------------------------------------------------------------------
# Step 2: build the JSON payload (the token's claims).
#
#   username   - the user the token is issued to.
#   patientId  - only present when studies are identified by accession number.
#   studies    - the studies the user may open; each has a studyInstanceUid OR an accessionNumber.
#   expiresAt  - when the token stops being accepted, in seconds since the Unix epoch (UTC).
#   jti        - a unique ID for this token. Generate a new random value for every token; it lets
#                AdvaPACS reject a token that is presented more than once.
# ------------------------------------------------------------------------------------------------
def build_payload(args: argparse.Namespace) -> str:
    payload = {"username": args.username}

    if args.suid:
        payload["studies"] = [{"studyInstanceUid": uid} for uid in args.suid]
    else:
        payload["patientId"] = args.patientId
        payload["studies"] = [{"accessionNumber": acc} for acc in args.accNum]

    payload["expiresAt"] = int(time.time()) + args.expireAfter
    payload["jti"] = str(uuid.uuid4())

    return json.dumps(payload, separators=(",", ":"))


# ------------------------------------------------------------------------------------------------
# Step 3: protect the payload with your access key.
#
#   Key derivation: the 256-bit key is SHA-256(UTF-8 bytes of the access key secret).
#                   Use the hash, not the raw secret.
#   Key ID:         the access key ID goes in the `kid` header so AdvaPACS knows which key to use.
#   JWE (recommended): alg A256KW, enc A256GCM. The payload is encrypted, so patient
#                      identifiers (PHI) can't leak into server logs, proxies or browser
#                      history, and it can't be altered.
#   JWS:               alg HS256. Tamper-proof, but the payload is only base64url-encoded,
#                      so anyone who sees the token can read it. Use only if you can't use JWE.
# ------------------------------------------------------------------------------------------------
def derive_key(access_key_secret: str) -> jwk.JWK:
    key_bytes = hashlib.sha256(access_key_secret.encode("utf-8")).digest()
    return jwk.JWK(kty="oct", k=base64url_encode(key_bytes))


def sign(payload: str, access_key_id: str, key: jwk.JWK) -> str:
    token = jws.JWS(payload.encode("utf-8"))
    token.add_signature(key, None, protected=json.dumps({"alg": "HS256", "kid": access_key_id}))
    return token.serialize(compact=True)


def encrypt(payload: str, access_key_id: str, key: jwk.JWK) -> str:
    header = {"alg": "A256KW", "enc": "A256GCM", "kid": access_key_id}
    token = jwe.JWE(payload.encode("utf-8"), protected=json.dumps(header))
    token.add_recipient(key)
    return token.serialize(compact=True)


# ------------------------------------------------------------------------------------------------

def main() -> None:
    args = read_inputs()
    payload = build_payload(args)

    if args.mode == "json":
        # Debug output only: this payload is NOT protected and must not be used as a token.
        print(payload)
        return

    key = derive_key(args.accessKeySecret)
    if args.mode == "jwe":
        print(encrypt(payload, args.accessKeyId, key))  # recommended
    else:
        print(sign(payload, args.accessKeyId, key))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001 - surface any failure as a clean CLI error
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
