'''
Testing module for the Session Pro Backend, testing internal and public APIs.

The backend tests call the DB APIs directly to test the outcome on the tables in the SQLite
database.

The server tests spins up a local Flask instance as per
(https://flask.palletsprojects.com/en/stable/testing/#sending-requests-with-the-test-client) and
sends a request using the test client and we vet the request and response produced by hitting said
endpoint.

TODO:
  - Test that modifying the salt breaks verification
'''

import flask
import json
import nacl.signing
import nacl.bindings
import nacl.public
import os
import time
import werkzeug
import dataclasses

from platform_google_types import GoogleDuration
from vendor import onion_req
import backend
import base
import server

def test_backend_same_user_stacks_subscription():
    # Setup DB
    err                       = base.ErrorSink()
    db: backend.SetupDBResult = backend.setup_db(path=':memory:', uri=False, err=err)
    assert len(err.msg_list) == 0, f'{err.msg_list}'
    assert db.sql_conn

    # Setup scenarios, single user who stacks a subscription
    backend_key:         nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    master_key:          nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    rotating_key:        nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    redeemed_unix_ts_ms: int                     = base.round_unix_ts_ms_to_next_day(int(time.time() * 1000))

    @dataclasses.dataclass
    class Scenario:
        google_payment_token:    str                          = ''
        google_order_id:         str                          = ''
        subscription_duration_s: int                          = 0
        proof:                   backend.ProSubscriptionProof = dataclasses.field(default_factory=backend.ProSubscriptionProof)
        payment_provider:        base.PaymentProvider         = base.PaymentProvider.Nil
        expiry_unix_ts_ms:       int                          = 0
        grace_unix_ts_ms:        int                          = 0

    scenarios: list[Scenario] = [
        Scenario(google_payment_token    = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
                 google_order_id         = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
                 subscription_duration_s = 30 * base.SECONDS_IN_DAY,
                 expiry_unix_ts_ms       = redeemed_unix_ts_ms + ((30 * base.SECONDS_IN_DAY) * 1000),
                 grace_unix_ts_ms        = 0,
                 payment_provider        = base.PaymentProvider.GooglePlayStore),

        Scenario(google_payment_token    = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
                 google_order_id         = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
                 subscription_duration_s = 365 * base.SECONDS_IN_DAY,
                 expiry_unix_ts_ms       = redeemed_unix_ts_ms + ((31 * base.SECONDS_IN_DAY) * 1000),
                 grace_unix_ts_ms        = 0,
                 payment_provider        = base.PaymentProvider.GooglePlayStore)
    ]

    for it in scenarios:
        # Add the "unredeemed" version of the payment, e.g. mock the notification from
        # IOS App Store/Google Play Store
        assert it.payment_provider == base.PaymentProvider.GooglePlayStore, "Currently only google is mocked"
        payment_tx                      = backend.PaymentProviderTransaction()
        payment_tx.provider             = it.payment_provider
        payment_tx.google_payment_token = it.google_payment_token
        payment_tx.google_order_id      = it.google_order_id
        backend.add_unredeemed_payment(sql_conn=db.sql_conn,
                                       payment_tx=payment_tx,
                                       subscription_duration_s=it.subscription_duration_s,
                                       expiry_unix_ts_ms=it.expiry_unix_ts_ms,
                                       grace_unix_ts_ms=it.grace_unix_ts_ms,
                                       err=err)
        assert len(err.msg_list) == 0

        unredeemed_payment_list: list[backend.PaymentRow] = backend.get_unredeemed_payments_list(db.sql_conn)
        assert len(unredeemed_payment_list)                       == 1
        assert unredeemed_payment_list[0].status                  == backend.PaymentStatus.Unredeemed
        assert unredeemed_payment_list[0].payment_provider        == it.payment_provider
        assert unredeemed_payment_list[0].redeemed_unix_ts_ms     == None
        assert unredeemed_payment_list[0].expiry_unix_ts_ms       == it.expiry_unix_ts_ms
        assert unredeemed_payment_list[0].refunded_unix_ts_ms     == None
        assert unredeemed_payment_list[0].google_payment_token    == it.google_payment_token
        assert unredeemed_payment_list[0].google_order_id         == it.google_order_id
        assert unredeemed_payment_list[0].subscription_duration_s == it.subscription_duration_s

        # Register the payment
        version: int = 0
        add_pro_payment_tx                      = backend.AddProPaymentUserTransaction()
        add_pro_payment_tx.provider             = payment_tx.provider
        add_pro_payment_tx.google_payment_token = payment_tx.google_payment_token
        add_pro_payment_tx.google_order_id      = payment_tx.google_order_id

        add_payment_hash: bytes = backend.make_add_pro_payment_hash(version=version,
                                                                    master_pkey=master_key.verify_key,
                                                                    rotating_pkey=rotating_key.verify_key,
                                                                    payment_tx=add_pro_payment_tx)

        it.proof = backend.add_pro_payment(version             = version,
                                           sql_conn            = db.sql_conn,
                                           signing_key         = backend_key,
                                           redeemed_unix_ts_ms = redeemed_unix_ts_ms,
                                           master_pkey         = master_key.verify_key,
                                           rotating_pkey       = rotating_key.verify_key,
                                           payment_tx          = add_pro_payment_tx,
                                           master_sig          = master_key.sign(add_payment_hash).signature,
                                           rotating_sig        = rotating_key.sign(add_payment_hash).signature,
                                           err                 = err)

        # Verify payment was redeemed
        unredeemed_payment_list = backend.get_unredeemed_payments_list(db.sql_conn)
        assert len(unredeemed_payment_list) == 0

    runtime: backend.RuntimeRow                             = backend.get_runtime(db.sql_conn)
    assert runtime.gen_index                               == 2

    user_list: list[backend.UserRow]                        = backend.get_users_list(db.sql_conn)
    assert len(user_list)                                  == 1
    assert user_list[0].master_pkey                        == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(user_list[0].master_pkey.hex(), bytes(master_key.verify_key).hex())
    assert user_list[0].gen_index                          == runtime.gen_index - 1
    assert user_list[0].expiry_unix_ts_ms                  == scenarios[1].expiry_unix_ts_ms

    payment_list: list[backend.PaymentRow]                  = backend.get_payments_list(db.sql_conn)
    assert len(payment_list)                               == 2
    assert payment_list[0].master_pkey                     == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(payment_list[0].master_pkey.hex(), bytes(master_key.verify_key).hex())
    assert payment_list[0].subscription_duration_s         == scenarios[0].subscription_duration_s
    assert payment_list[0].payment_provider                == scenarios[0].payment_provider
    assert payment_list[0].redeemed_unix_ts_ms             == redeemed_unix_ts_ms
    assert payment_list[0].expiry_unix_ts_ms               == scenarios[0].expiry_unix_ts_ms
    assert payment_list[0].refunded_unix_ts_ms             is None
    assert payment_list[0].google_payment_token            == scenarios[0].google_payment_token
    assert len(payment_list[0].apple.tx_id)                == 0
    assert len(payment_list[0].apple.original_tx_id)       == 0
    assert len(payment_list[0].apple.web_line_order_tx_id) == 0

    assert payment_list[1].master_pkey                     == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(payment_list[0].master_pkey.hex(), bytes(master_key.verify_key).hex())
    assert payment_list[1].subscription_duration_s         == scenarios[1].subscription_duration_s
    assert payment_list[1].payment_provider                == scenarios[1].payment_provider
    assert payment_list[1].redeemed_unix_ts_ms             == redeemed_unix_ts_ms
    assert payment_list[1].expiry_unix_ts_ms               == scenarios[1].expiry_unix_ts_ms
    assert payment_list[1].refunded_unix_ts_ms             is None
    assert payment_list[1].google_payment_token            == scenarios[1].google_payment_token
    assert len(payment_list[0].apple.tx_id)                == 0
    assert len(payment_list[0].apple.original_tx_id)       == 0
    assert len(payment_list[0].apple.web_line_order_tx_id) == 0

    revocation_list: list[backend.RevocationRow]            = backend.get_revocations_list(db.sql_conn)
    assert len(revocation_list)                            == 1
    assert revocation_list[0].gen_index                    == 0
    assert revocation_list[0].expiry_unix_ts_ms            == scenarios[0].expiry_unix_ts_ms

    expire_result: backend.ExpireResult                     = backend.expire_payments_revocations_and_users(db.sql_conn, unix_ts_ms=scenarios[0].expiry_unix_ts_ms)
    assert expire_result.already_done_by_someone_else      == False
    assert expire_result.success                           == True
    assert expire_result.payments                          == 1
    assert expire_result.revocations                       == 1
    assert expire_result.users                             == 0

    # NOTE: Update the latest payments expiry and grace period
    payment_tx                                              = backend.PaymentProviderTransaction()
    payment_tx.provider                                     = scenarios[1].payment_provider
    payment_tx.google_payment_token                         = scenarios[1].google_payment_token
    payment_tx.google_order_id                              = scenarios[1].google_order_id
    new_expiry_unix_ts_ms                                   = scenarios[1].expiry_unix_ts_ms + 1000
    new_grace_unix_ts_ms                                    = scenarios[1].expiry_unix_ts_ms + 2000
    updated: bool                                           = backend.update_payment_unix_ts_ms(sql_conn=db.sql_conn, payment_tx=payment_tx, expiry_unix_ts_ms=new_expiry_unix_ts_ms, grace_unix_ts_ms=new_grace_unix_ts_ms, err=err)
    assert updated

    # NOTE: Verify that the new grace and expiry were assigned to the user
    payment_list: list[backend.PaymentRow]                  = backend.get_payments_list(db.sql_conn)
    assert len(payment_list)                               == 2
    assert payment_list[0].master_pkey                     == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(payment_list[0].master_pkey.hex(), bytes(master_key.verify_key).hex())
    assert payment_list[0].subscription_duration_s         == scenarios[0].subscription_duration_s
    assert payment_list[0].payment_provider                == scenarios[0].payment_provider
    assert payment_list[0].redeemed_unix_ts_ms             == redeemed_unix_ts_ms
    assert payment_list[0].expiry_unix_ts_ms               == scenarios[0].expiry_unix_ts_ms
    assert payment_list[0].grace_unix_ts_ms                == scenarios[0].grace_unix_ts_ms
    assert payment_list[0].refunded_unix_ts_ms             is None
    assert payment_list[0].google_payment_token            == scenarios[0].google_payment_token
    assert len(payment_list[0].apple.tx_id)                == 0
    assert len(payment_list[0].apple.original_tx_id)       == 0
    assert len(payment_list[0].apple.web_line_order_tx_id) == 0

    assert payment_list[1].master_pkey                     == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(payment_list[0].master_pkey.hex(), bytes(master_key.verify_key).hex())
    assert payment_list[1].subscription_duration_s         == scenarios[1].subscription_duration_s
    assert payment_list[1].payment_provider                == scenarios[1].payment_provider
    assert payment_list[1].redeemed_unix_ts_ms             == redeemed_unix_ts_ms
    assert payment_list[1].expiry_unix_ts_ms               == new_expiry_unix_ts_ms
    assert payment_list[1].grace_unix_ts_ms                == new_grace_unix_ts_ms
    assert payment_list[1].refunded_unix_ts_ms             is None
    assert payment_list[1].google_payment_token            == scenarios[1].google_payment_token
    assert len(payment_list[0].apple.tx_id)                == 0
    assert len(payment_list[0].apple.original_tx_id)       == 0
    assert len(payment_list[0].apple.web_line_order_tx_id) == 0

    # NOTE: Get the user and payments and verify that the expiry and grace are correct
    with base.SQLTransaction(db.sql_conn) as tx:
        get: backend.GetUserAndPayments = backend.get_user_and_payments(tx=tx, master_pkey=master_key.verify_key)
        assert get.latest_expiry_unix_ts_ms == new_expiry_unix_ts_ms
        assert get.latest_grace_unix_ts_ms  == new_grace_unix_ts_ms

    _ = backend.verify_db(db.sql_conn, err)
    if len(err.msg_list) > 0:
        for it in err.msg_list:
            print(f"ERROR: {it}")
        assert len(err.msg_list) == 0

def test_server_add_payment_flow():
    # Setup DB
    err                       = base.ErrorSink()
    db: backend.SetupDBResult = backend.setup_db(path='file:test_server_db?mode=memory&cache=shared', uri=True, err=err)
    assert len(err.msg_list) == 0, f'{err.msg_list}'
    assert db.sql_conn

    # Setup local flask instance
    flask_app:    flask.Flask     = server.init(testing_mode=True,
                                                db_path=db.path,
                                                db_path_is_uri=True,
                                                server_x25519_skey=db.runtime.backend_key.to_curve25519_private_key())
    flask_client: werkzeug.Client = flask_app.test_client()

    # Setup keys for onion requests
    server_x25519_skey = db.runtime.backend_key.to_curve25519_private_key()
    our_x25519_skey    = nacl.public.PrivateKey.generate()
    shared_key: bytes  = onion_req.make_shared_key(our_x25519_skey=our_x25519_skey,
                                                   server_x25519_pkey=server_x25519_skey.public_key)

    # Register an unredeemed payment (by writing the the token to the DB directly)
    unix_ts_ms: int                 = int(time.time() * 1000)
    next_day_unix_ts_ms: int        = base.round_unix_ts_ms_to_next_day(unix_ts_ms)
    master_key                      = nacl.signing.SigningKey.generate()
    rotating_key                    = nacl.signing.SigningKey.generate()
    payment_tx                      = backend.PaymentProviderTransaction()
    payment_tx.provider             = base.PaymentProvider.GooglePlayStore
    payment_tx.google_payment_token = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
    payment_tx.google_order_id      = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
    backend.add_unredeemed_payment(sql_conn=db.sql_conn,
                                   payment_tx=payment_tx,
                                   subscription_duration_s=30 * base.SECONDS_IN_DAY,
                                   expiry_unix_ts_ms=next_day_unix_ts_ms + ((base.SECONDS_IN_DAY * 30) * 1000),
                                   grace_unix_ts_ms=0,
                                   err=err)
    assert len(err.msg_list) == 0, f'{err.msg_list}'

    first_gen_index_hash:   bytes = b''
    first_expiry_unix_ts_ms: int = 0
    if 1: # Grab the pro status before anything has happened
        version:      int   = 0
        history:      bool  = True
        hash_to_sign: bytes = server.make_get_all_payments_hash(version=version, master_pkey=master_key.verify_key, unix_ts_ms=unix_ts_ms, history=history)
        request_body={'version':     version,
                      'master_pkey': bytes(master_key.verify_key).hex(),
                      'master_sig':  bytes(master_key.sign(hash_to_sign).signature).hex(),
                      'unix_ts_ms':  unix_ts_ms,
                      'history':     history}

        onion_request = onion_req.make_request_v4(our_x25519_pkey=our_x25519_skey.public_key,
                                                  shared_key=shared_key,
                                                  endpoint=server.ROUTE_GET_PRO_STATUS,
                                                  request_body=request_body)

        # POST and get response
        response:       werkzeug.test.TestResponse = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
        onion_response: onion_req.Response         = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
        assert onion_response.success

        # Parse the JSON from the response
        response_json = json.loads(onion_response.body)
        assert isinstance(response_json, dict), f'Response {onion_response.body}'

        # Parse status from response
        assert response_json['status'] == 0, f'Response was: {json.dumps(response_json, indent=2)}'
        assert 'errors' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

        # Parse result object is at root
        assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
        result_json = response_json['result']

        # Extract the fields
        result_version: int                        = base.json_dict_require_int(d=result_json, key='version',  err=err)
        result_items:   list[dict[str, int | str]] = base.json_dict_require_array(d=result_json, key='items',  err=err)
        result_status:  int                        = base.json_dict_require_int(d=result_json, key='status',  err=err)
        assert len(err.msg_list) == 0,                                       '{err.msg_list}'
        assert result_status     == server.UserProStatus.NeverBeenPro.value, f'Response was: {json.dumps(response_json, indent=2)}'
        assert len(result_items) == 0,                                       f'Response was: {json.dumps(response_json, indent=2)}'

    if 1: # Simulate client request to register a payment
        version: int                            = 0
        add_pro_payment_tx                      = backend.AddProPaymentUserTransaction()
        add_pro_payment_tx.provider             = payment_tx.provider
        add_pro_payment_tx.google_payment_token = payment_tx.google_payment_token

        payment_hash_to_sign: bytes = backend.make_add_pro_payment_hash(version=version,
                                                                        master_pkey=master_key.verify_key,
                                                                        rotating_pkey=rotating_key.verify_key,
                                                                        payment_tx=add_pro_payment_tx)

        onion_request = onion_req.make_request_v4(our_x25519_pkey=our_x25519_skey.public_key,
                                                  shared_key=shared_key,
                                                  endpoint=server.ROUTE_ADD_PRO_PAYMENT,
                                                  request_body={
                                                      'version':              version,
                                                      'master_pkey':          bytes(master_key.verify_key).hex(),
                                                      'rotating_pkey':        bytes(rotating_key.verify_key).hex(),
                                                      'master_sig':           bytes(master_key.sign(payment_hash_to_sign).signature).hex(),
                                                      'rotating_sig':         bytes(rotating_key.sign(payment_hash_to_sign).signature).hex(),
                                                      'payment_tx': {
                                                          'provider':             add_pro_payment_tx.provider.value,
                                                          'google_payment_token': add_pro_payment_tx.google_payment_token,
                                                      }
                                                  })

        # POST and get response
        response:       werkzeug.test.TestResponse = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
        onion_response: onion_req.Response         = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
        assert onion_response.success

        # Parse the JSON from the response
        response_json = json.loads(onion_response.body)
        assert isinstance(response_json, dict), f'Response {onion_response.body}'

        # Parse status from response
        assert response_json['status'] == 0,  f'Response was: {json.dumps(response_json, indent=2)}'
        assert 'errors' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

        # Parse result object is at root
        assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
        result_json = response_json['result']

        # Extract the fields
        assert isinstance(result_json, dict)
        result_version:            int = base.json_dict_require_int(d=result_json, key='version',          err=err)
        result_gen_index_hash_hex: str = base.json_dict_require_str(d=result_json, key='gen_index_hash',   err=err)
        result_rotating_pkey_hex:  str = base.json_dict_require_str(d=result_json, key='rotating_pkey',    err=err)
        result_expiry_unix_ts_ms:  int = base.json_dict_require_int(d=result_json, key='expiry_unix_ts_ms', err=err)
        result_sig_hex:            str = base.json_dict_require_str(d=result_json, key='sig',              err=err)
        assert len(err.msg_list) == 0, '{err.msg_list}'

        # Parse hex fields to bytes
        result_rotating_pkey  = nacl.signing.VerifyKey(base.hex_to_bytes(hex=result_rotating_pkey_hex,  label='Rotating public key',   hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2, err=err))
        result_sig            =                        base.hex_to_bytes(hex=result_sig_hex,            label='Signature',             hex_len=nacl.bindings.crypto_sign_BYTES * 2,          err=err)
        result_gen_index_hash =                        base.hex_to_bytes(hex=result_gen_index_hash_hex, label='Generation index hash', hex_len=backend.BLAKE2B_DIGEST_SIZE * 2, err=err)
        assert len(err.msg_list) == 0, '{err.msg_list}'

        # Check the rotating key returned matches what we asked the server to sign
        assert result_rotating_pkey == rotating_key.verify_key

        # Check that the server signed our proof w/ their public key
        proof_hash: bytes = backend.build_proof_hash(result_version,
                                                     result_gen_index_hash,
                                                     result_rotating_pkey,
                                                     result_expiry_unix_ts_ms)
        _ = db.runtime.backend_key.verify_key.verify(smessage=proof_hash, signature=result_sig)

        first_gen_index_hash   = result_gen_index_hash
        first_expiry_unix_ts_ms = result_expiry_unix_ts_ms

    if 1: # Authorise a new rotated key for the pro subscription
        new_rotating_key    = nacl.signing.SigningKey.generate()
        version             = 0
        unix_ts_ms          = int(time.time() * 1000)
        hash_to_sign: bytes = backend.make_get_pro_proof_hash(version=version,
                                                              master_pkey=master_key.verify_key,
                                                              rotating_pkey=new_rotating_key.verify_key,
                                                              unix_ts_ms=unix_ts_ms)

        request_body = {
            'version':       version,
            'master_pkey':   bytes(master_key.verify_key).hex(),
            'rotating_pkey': bytes(new_rotating_key.verify_key).hex(),
            'unix_ts_ms':     unix_ts_ms,
            'master_sig':    bytes(master_key.sign(hash_to_sign).signature).hex(),
            'rotating_sig':  bytes(new_rotating_key.sign(hash_to_sign).signature).hex(),
        }

        onion_request = onion_req.make_request_v4(our_x25519_pkey=our_x25519_skey.public_key,
                                                  shared_key=shared_key,
                                                  endpoint=server.ROUTE_GET_PRO_PROOF,
                                                  request_body=request_body)

        # POST and get response
        response:       werkzeug.test.TestResponse = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
        onion_response: onion_req.Response         = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
        assert onion_response.success

        # Parse the JSON from the response
        response_json = json.loads(onion_response.body)
        assert isinstance(response_json, dict), f'Response {onion_response.body}'

        # Parse status from response
        assert response_json['status'] == 0, f'Response was: {json.dumps(response_json, indent=2)}'
        assert 'errors' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

        # Parse result object is at root
        assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
        result_json = response_json['result']

        # Extract the fields
        result_version:            int = base.json_dict_require_int(d=result_json, key='version',          err=err)
        result_gen_index_hash_hex: str = base.json_dict_require_str(d=result_json, key='gen_index_hash',   err=err)
        result_rotating_pkey_hex:  str = base.json_dict_require_str(d=result_json, key='rotating_pkey',    err=err)
        result_expiry_unix_ts_ms:   int = base.json_dict_require_int(d=result_json, key='expiry_unix_ts_ms', err=err)
        result_sig_hex:            str = base.json_dict_require_str(d=result_json, key='sig',              err=err)
        assert len(err.msg_list) == 0, '{err.msg_list}'

        # Parse hex fields to bytes
        result_rotating_pkey  = nacl.signing.VerifyKey(base.hex_to_bytes(hex=result_rotating_pkey_hex,  label='Rotating public key',   hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2, err=err))
        result_sig            =                        base.hex_to_bytes(hex=result_sig_hex,            label='Signature',             hex_len=nacl.bindings.crypto_sign_BYTES * 2,          err=err)
        result_gen_index_hash =                        base.hex_to_bytes(hex=result_gen_index_hash_hex, label='Generation index hash', hex_len=backend.BLAKE2B_DIGEST_SIZE * 2,              err=err)
        assert len(err.msg_list) == 0, '{err.msg_list}'

        # Check the rotating key returned matches what we asked the server to sign
        assert result_rotating_pkey == new_rotating_key.verify_key

        # Check that the server signed our proof w/ their public key
        proof_hash = backend.build_proof_hash(result_version,
                                              result_gen_index_hash,
                                              result_rotating_pkey,
                                              result_expiry_unix_ts_ms)
        _ = db.runtime.backend_key.verify_key.verify(smessage=proof_hash, signature=result_sig)

    if 1: # Register another payment on the same user, this will revoke the old proof
        version: int                        = 0
        new_payment_tx                      = backend.PaymentProviderTransaction()
        new_payment_tx.provider             = base.PaymentProvider.GooglePlayStore
        new_payment_tx.google_payment_token = os.urandom(len(payment_tx.google_payment_token)).hex()
        new_payment_tx.google_order_id      = os.urandom(len(payment_tx.google_payment_token)).hex()
        backend.add_unredeemed_payment(sql_conn=db.sql_conn,
                                       payment_tx=new_payment_tx,
                                       subscription_duration_s=30 * base.SECONDS_IN_DAY,
                                       expiry_unix_ts_ms=unix_ts_ms + ((base.SECONDS_IN_DAY * 30) * 1000),
                                       grace_unix_ts_ms=0,
                                       err=err)

        new_add_pro_payment_tx                      = backend.AddProPaymentUserTransaction()
        new_add_pro_payment_tx.provider             = new_payment_tx.provider
        new_add_pro_payment_tx.google_payment_token = new_payment_tx.google_payment_token
        payment_hash_to_sign: bytes = backend.make_add_pro_payment_hash(version=version,
                                                                        master_pkey=master_key.verify_key,
                                                                        rotating_pkey=rotating_key.verify_key,
                                                                        payment_tx=new_add_pro_payment_tx)

        request_body = {
            'version':              version,
            'master_pkey':          bytes(master_key.verify_key).hex(),
            'rotating_pkey':        bytes(rotating_key.verify_key).hex(),
            'master_sig':           bytes(master_key.sign(payment_hash_to_sign).signature).hex(),
            'rotating_sig':         bytes(rotating_key.sign(payment_hash_to_sign).signature).hex(),
            'payment_tx': {
                'provider':             new_add_pro_payment_tx.provider.value,
                'google_payment_token': new_add_pro_payment_tx.google_payment_token,
            }
        }

        onion_request = onion_req.make_request_v4(our_x25519_pkey=our_x25519_skey.public_key,
                                                  shared_key=shared_key,
                                                  endpoint=server.ROUTE_ADD_PRO_PAYMENT,
                                                  request_body=request_body)

        # POST and get response
        response:       werkzeug.test.TestResponse = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
        onion_response: onion_req.Response         = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
        assert onion_response.success

        # Parse the JSON from the response
        response_json = json.loads(onion_response.body)
        assert isinstance(response_json, dict), f'Response {onion_response.body}'

        # Parse status from response
        assert response_json['status'] == 0, f'Response was: {json.dumps(response_json, indent=2)}'
        assert 'errors' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

        # Parse result object is at root
        assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
        result_json = response_json['result']

        # Extract the fields
        result_version:            int = base.json_dict_require_int(d=result_json, key='version',          err=err)
        result_gen_index_hash_hex: str = base.json_dict_require_str(d=result_json, key='gen_index_hash',   err=err)
        result_rotating_pkey_hex:  str = base.json_dict_require_str(d=result_json, key='rotating_pkey',    err=err)
        result_expiry_unix_ts_ms:  int = base.json_dict_require_int(d=result_json, key='expiry_unix_ts_ms', err=err)
        result_sig_hex:            str = base.json_dict_require_str(d=result_json, key='sig',              err=err)
        assert len(err.msg_list) == 0, '{err.msg_list}'

        # Parse hex fields to bytes
        result_rotating_pkey         = nacl.signing.VerifyKey(base.hex_to_bytes(hex=result_rotating_pkey_hex,  label='Rotating public key',   hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2, err=err))
        result_sig:            bytes =                        base.hex_to_bytes(hex=result_sig_hex,            label='Signature',             hex_len=nacl.bindings.crypto_sign_BYTES * 2,          err=err)
        result_gen_index_hash: bytes =                        base.hex_to_bytes(hex=result_gen_index_hash_hex, label='Generation index hash', hex_len=backend.BLAKE2B_DIGEST_SIZE * 2,              err=err)
        assert len(err.msg_list) == 0, '{err.msg_list}'

        # Check the rotating key returned matches what we asked the server to sign
        assert result_rotating_pkey == rotating_key.verify_key

        # Check that the server signed our proof w/ their public key
        proof_hash: bytes = backend.build_proof_hash(result_version,
                                                        result_gen_index_hash,
                                                        result_rotating_pkey,
                                                        result_expiry_unix_ts_ms)
        _ = db.runtime.backend_key.verify_key.verify(smessage=proof_hash, signature=result_sig)

    curr_revocation_ticket: int = 0
    if 1: # Get the revocation list
        request_body={'version': 0, 'ticket':  0}
        onion_request = onion_req.make_request_v4(our_x25519_pkey=our_x25519_skey.public_key,
                                                  shared_key=shared_key,
                                                  endpoint=server.ROUTE_GET_PRO_REVOCATIONS,
                                                  request_body=request_body)

        # POST and get response
        response:       werkzeug.test.TestResponse = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
        onion_response: onion_req.Response         = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
        assert onion_response.success

        # Parse the JSON from the response
        response_json = json.loads(onion_response.body)
        assert isinstance(response_json, dict), f'Response {onion_response.body}'

        # Parse status from response
        assert response_json['status'] == 0, f'Response was: {json.dumps(response_json, indent=2)}'
        assert 'errors' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

        # Parse result object is at root
        assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
        result_json = response_json['result']

        # Extract the fields
        result_version: int                        = base.json_dict_require_int(d=result_json, key='version', err=err)
        result_items:   list[dict[str, int | str]] = base.json_dict_require_array(d=result_json, key='items', err=err)
        result_ticket:  int                        = base.json_dict_require_int(d=result_json, key='ticket',  err=err)
        assert len(err.msg_list) == 0, '{err.msg_list}'
        assert result_version == 0
        assert result_ticket  == 1
        curr_revocation_ticket = result_ticket

        # Check that the server returned the revocation list with the iniital
        # payment that got revoked after we stacked a new subscription ontop
        assert len(result_items) == 1
        for it in result_items:
            it: dict[str, int | str]
            assert 'expiry_unix_ts_ms' in it and isinstance(it['expiry_unix_ts_ms'], int)
            assert 'gen_index_hash'   in it and isinstance(it['gen_index_hash'], str)
            assert it['gen_index_hash']   == first_gen_index_hash.hex()
            assert it['expiry_unix_ts_ms'] == first_expiry_unix_ts_ms

    # Try grabbing the revocation again with the current ticket (we should get
    # an empty list because we passed in the most up to date ticket)
    if 1:
        onion_request = onion_req.make_request_v4(our_x25519_pkey=our_x25519_skey.public_key,
                                                  shared_key=shared_key,
                                                  endpoint=server.ROUTE_GET_PRO_REVOCATIONS,
                                                  request_body={'version': 0, 'ticket':  curr_revocation_ticket})

        # POST and get response
        response:       werkzeug.test.TestResponse = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
        onion_response: onion_req.Response         = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
        assert onion_response.success

        # Parse the JSON from the response
        response_json = json.loads(onion_response.body)
        assert isinstance(response_json, dict), f'Response {onion_response.body}'

        # Parse status from response
        assert response_json['status'] == 0, f'Response was: {json.dumps(response_json, indent=2)}'
        assert 'errors' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

        # Parse result object is at root
        assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
        result_json = response_json['result']

        # Extract the fields
        result_version: int                        = base.json_dict_require_int(d=result_json, key='version', err=err)
        result_items:   list[dict[str, int | str]] = base.json_dict_require_array(d=result_json, key='items', err=err)
        result_ticket:  int                        = base.json_dict_require_int(d=result_json, key='ticket',  err=err)
        assert len(err.msg_list) == 0, '{err.msg_list}'
        assert result_version == 0, f'Response was: {json.dumps(response_json, indent=2)}'
        assert result_ticket  == 1, f'Response was: {json.dumps(response_json, indent=2)}'

        # List should be empty because we passed in the newest revocation
        # ticket. There are no changes to the revocation list so the backend
        # will return an empty list
        assert len(result_items) == 0, f'Response was: {json.dumps(response_json, indent=2)}'

    # Get the pro status now w/ a bunch of payments
    if 1:
        version:      int   = 0
        unix_ts_ms:   int   = int(time.time() * 1000)
        history:      bool  = True
        hash_to_sign: bytes = server.make_get_all_payments_hash(version=version, master_pkey=master_key.verify_key, unix_ts_ms=unix_ts_ms, history=history)

        request_body={'version':     version,
                      'master_pkey': bytes(master_key.verify_key).hex(),
                      'master_sig':  bytes(master_key.sign(hash_to_sign).signature).hex(),
                      'unix_ts_ms':   unix_ts_ms,
                      'history':     history}

        onion_request = onion_req.make_request_v4(our_x25519_pkey=our_x25519_skey.public_key,
                                                  shared_key=shared_key,
                                                  endpoint=server.ROUTE_GET_PRO_STATUS,
                                                  request_body=request_body)

        # POST and get response
        response:       werkzeug.test.TestResponse = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
        onion_response: onion_req.Response         = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
        assert onion_response.success

        # Parse the JSON from the response
        response_json = json.loads(onion_response.body)
        assert isinstance(response_json, dict), f'Response {onion_response.body}'

        # Parse status from response
        assert response_json['status'] == 0, f'Response was: {json.dumps(response_json, indent=2)}'
        assert 'errors' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

        # Parse result object is at root
        assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
        result_json = response_json['result']

        # Extract the fields
        result_version: int                        = base.json_dict_require_int(d=result_json, key='version',  err=err)
        result_items:   list[dict[str, int | str]] = base.json_dict_require_array(d=result_json, key='items',  err=err)
        result_status:  int                        = base.json_dict_require_int(d=result_json, key='status',  err=err)
        assert len(err.msg_list) == 0,                                 '{err.msg_list}'
        assert result_status     == server.UserProStatus.Active.value, f'Response was: {json.dumps(response_json, indent=2)}'
        assert len(result_items) == 2,                                 f'Response was: {json.dumps(response_json, indent=2)}'

        # Retry the request but use a too old timestamp
        if 1:
            unix_ts_ms:   int   = int((time.time() * 1000) + (server.GET_ALL_PAYMENTS_MAX_TIMESTAMP_DELTA_MS * 2))
            hash_to_sign: bytes = server.make_get_all_payments_hash(version=version, master_pkey=master_key.verify_key, unix_ts_ms=unix_ts_ms, history=history)
            onion_request = onion_req.make_request_v4(our_x25519_pkey=our_x25519_skey.public_key,
                                                      shared_key=shared_key,
                                                      endpoint=server.ROUTE_GET_PRO_STATUS,
                                                      request_body={'version':     version,
                                                                    'master_pkey': bytes(master_key.verify_key).hex(),
                                                                    'master_sig':  bytes(master_key.sign(hash_to_sign).signature).hex(),
                                                                    'unix_ts_ms':   unix_ts_ms,
                                                                    'history':     history})

            # POST and get response
            response:       werkzeug.test.TestResponse = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
            onion_response: onion_req.Response         = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
            assert onion_response.success

            # Parse the JSON from the response
            response_json = json.loads(onion_response.body)
            assert isinstance(response_json, dict), f'Response {onion_response.body}'

            # Parse status from response
            assert response_json['status'] == 1,     f'Response was: {json.dumps(response_json, indent=2)}'
            assert len(response_json['errors']) > 0, f'Response was: {json.dumps(response_json, indent=2)}'
            assert 'result' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

        # Retry the request but create a hash with the rotating key
        if 1:
            unix_ts_ms:    int   = int(time.time() * 1000)
            history:       bool  = True
            hash_to_sign:  bytes = server.make_get_all_payments_hash(version=version, master_pkey=rotating_key.verify_key, unix_ts_ms=unix_ts_ms, history=history)
            onion_request = onion_req.make_request_v4(our_x25519_pkey=our_x25519_skey.public_key,
                                                      shared_key=shared_key,
                                                      endpoint=server.ROUTE_GET_PRO_STATUS,
                                                      request_body={'version':     version,
                                                                    'master_pkey': bytes(master_key.verify_key).hex(),
                                                                    'master_sig':  bytes(master_key.sign(hash_to_sign).signature).hex(),
                                                                    'unix_ts_ms':   unix_ts_ms,
                                                                    'history':     history})

            # POST and get response
            response:       werkzeug.test.TestResponse = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
            onion_response: onion_req.Response         = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
            assert onion_response.success

            # Parse the JSON from the response
            response_json = json.loads(onion_response.body)
            assert isinstance(response_json, dict), f'Response {onion_response.body}'

            # Parse status from response
            assert response_json['status'] == 1,     f'Response was: {json.dumps(response_json, indent=2)}'
            assert len(response_json['errors']) > 0, f'Response was: {json.dumps(response_json, indent=2)}'
            assert 'result' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

        # Retry the request but with no history
        if 1:
            unix_ts_ms:    int  = int(time.time() * 1000)
            history:      bool  = False
            hash_to_sign: bytes = server.make_get_all_payments_hash(version=version, master_pkey=master_key.verify_key, unix_ts_ms=unix_ts_ms, history=history)
            onion_request = onion_req.make_request_v4(our_x25519_pkey=our_x25519_skey.public_key,
                                                      shared_key=shared_key,
                                                      endpoint=server.ROUTE_GET_PRO_STATUS,
                                                      request_body={'version':     version,
                                                                    'master_pkey': bytes(master_key.verify_key).hex(),
                                                                    'master_sig':  bytes(master_key.sign(hash_to_sign).signature).hex(),
                                                                    'unix_ts_ms':   unix_ts_ms,
                                                                    'history':     history})

            # POST and get response
            response:       werkzeug.test.TestResponse = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
            onion_response: onion_req.Response         = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
            assert onion_response.success

            # Parse the JSON from the response
            response_json = json.loads(onion_response.body)
            assert isinstance(response_json, dict), f'Response {onion_response.body}'
            result_json = response_json['result']

            # Parse status from response
            result_items:   list[dict[str, int | str]] = base.json_dict_require_array(d=result_json, key='items',  err=err)
            assert len(err.msg_list) == 0, '{err.msg_list}'
            assert len(result_items) == 0, f'Response was: {json.dumps(response_json, indent=2)}'

def test_onion_request_response_lifecycle():
    # Also call into and test the vendored onion request (as we are currently
    # maintaining a bleeding edge version of it).
    onion_req.test_onion_request_response_lifecycle()

def test_google_duration_parser():
    err = base.ErrorSink()

    MINUTE_S = 60
    HOUR_S = 60 * MINUTE_S
    DAY_S = 24 * HOUR_S

    test_cases = [
        ("P1D",         DAY_S), 
        ("P7D",         7 * DAY_S), 
        ("P14D",        14 * DAY_S), 
        ("P30D",        30 * DAY_S), 
        ("P1M",         30 * DAY_S), 
        ("P3M",         90 * DAY_S), 
        ("P12M",        12 * 30 * DAY_S), 
        ("P1Y",         365 * DAY_S), 
        ("P1DT1H",      25 * HOUR_S), 
        ("P1DT1H12M",   25 * HOUR_S + (12 * MINUTE_S)), 
        ("PT1S",        1),
        ("PT59S",       59),
        ("PT50M1S",     50 * MINUTE_S + 1),
    ]

    for string, seconds in test_cases:
        dur = GoogleDuration(string, err)
        assert dur.seconds == seconds, f' {seconds} != {dur.seconds} ({dur.iso8601})'
        assert dur.seconds * 1000 == dur.milliseconds
        assert not err.has()
