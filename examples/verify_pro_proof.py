"""
Example program to verify that a Session Pro Proof `signature` was signed by the `verify-pubkey`.
For example, given this output from the endpoint_example.py run on a development backend with a
hardcoded Ed25519 keypair (secret = [0xcd * 32]):

  Get Pro Proof
  Request:
  {
   "version": 0,
   "master_pkey": "162c30675ecc72ad17ef57e749a54284812cc178b1d2f31cfb3260f1f7594dc5",
   "rotating_pkey": "ecd0e9c371b5e1d9e116ba4d29b057e458c8b4bca40b5b3fea1cd5d5e89ae7b7",
   "unix_ts_ms": 1762407212143,
   "master_sig": "85462a36939e034e5ff4832943aab60056000a65f461cfdd058b5392068a88335c4db0507c37cf3fc7f73169cfba99d2f61a44999241078cb65bcf43d43e630d",
   "rotating_sig": "52de8c99bbfb7be78ad907848664e5efc746bedfaa074d8a28885fde51cad459be1c787b8626d7eaa52436b48d254ab038a2730c106b0e7e05177ea08da56d03"
  }
  Response: {
   "result": {
    "expiry_unix_ts_ms": 1762473660000,
    "gen_index_hash": "b330d8a3679ba0016169907bed1f49fa7d5ed8e1a73042197dd2949fecc7d174",
    "rotating_pkey": "ecd0e9c371b5e1d9e116ba4d29b057e458c8b4bca40b5b3fea1cd5d5e89ae7b7",
    "sig": "4537d985f6ec0134ed80537affd04be10f44a0f658cf26c6a3f48da43f5056a51b1ae48d2287bbed72e72c92ea87253357d466c7319c7d3514b081f9f1337d0e",
    "version": 0
   },
   "status": 0
  }

The produced Session Pro Proof should be verifiable by invoking this utility as per:

  python verify_pro_proof.py \
          --version 0 \
          --gen-index-hash b330d8a3679ba0016169907bed1f49fa7d5ed8e1a73042197dd2949fecc7d174 \
          --rotating-pubkey ecd0e9c371b5e1d9e116ba4d29b057e458c8b4bca40b5b3fea1cd5d5e89ae7b7 \
          --expiry-ts-ms 1762473660000 \
          --signature 4537d985f6ec0134ed80537affd04be10f44a0f658cf26c6a3f48da43f5056a51b1ae48d2287bbed72e72c92ea87253357d466c7319c7d3514b081f9f1337d0e \
          --verify-pubkey fc947730f49eb01427a66e050733294d9e520e545c7a27125a780634e0860a27

Which produces the output:

  Hash: 1fafd76b50fd486fef1694c98a1f14317de2329f5a1a653a8d46f53418151db5
  Signature valid: True
"""
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
import hashlib
import argparse

parser = argparse.ArgumentParser(description='Verify the given signature signed the Session Pro Proof elements (gen-index-hash, rotating-pubkey, expiry-ts-ms)')
_ = parser.add_argument('--version',         type=int, required=True, help='Session Pro Proof version')
_ = parser.add_argument('--gen-index-hash',  type=str, required=True, help='32-byte gen index hash (hex)')
_ = parser.add_argument('--rotating-pubkey', type=str, required=True, help='32-byte rotating pubkey (hex)')
_ = parser.add_argument('--expiry-ts-ms',    type=int, required=True, help='Expiry timestamp (ms)')
_ = parser.add_argument('--signature',       type=str,                help='64-byte Ed25519 signature (in hex) that the Pro Backend produced by signing the proof to verify')
_ = parser.add_argument('--verify-pubkey',   type=str,                help='32-byte Ed25519 pubkey (in hex) that the Pro Backend signed the proof with')
args = parser.parse_args()

# Compute hash of the proof
hash_result: bytes = b''
if 1:
    personalization = b"SeshProBackend__"
    h = hashlib.blake2b(person=personalization, digest_size=32)
    h.update(args.version.to_bytes(byteorder='little', length=1))

    # Strip 0x prefix if present and convert from hex
    gen_hash = args.gen_index_hash[2:] if args.gen_index_hash.startswith('0x') else args.gen_index_hash
    rot_pubkey = args.rotating_pubkey[2:] if args.rotating_pubkey.startswith('0x') else args.rotating_pubkey

    h.update(bytes.fromhex(gen_hash))
    h.update(bytes.fromhex(rot_pubkey))
    h.update(args.expiry_ts_ms.to_bytes(byteorder='little', length=8))
    hash_result = h.digest()
    print(f"Hash: {hash_result.hex()}")

# Verify that the signature signed the proof elements (gen-index-hash, rotating-pubkey, expiry-ts-ms) in question
if 1:
    if args.signature and args.verify_pubkey:
        sig_hex    = args.signature[2:] if args.signature.startswith('0x') else args.signature
        pubkey_hex = args.verify_pubkey[2:] if args.verify_pubkey.startswith('0x') else args.verify_pubkey
        sig        = bytes.fromhex(sig_hex)
        pubkey     = bytes.fromhex(pubkey_hex)
        assert len(hash_result) == 32, "Hash must be 32 bytes"
        assert len(sig)         == 64, "Invalid signature size"
        assert len(pubkey)      == 32, "Invalid public key size"
        try:
            verify_key = VerifyKey(pubkey)
            verify_key.verify(hash_result, signature=sig)
            print("Signature valid: True")
        except BadSignatureError:
            print("Signature valid: False")
