'''
Testing module for the Session Pro Backend, testing internal and public APIs.

The backend tests call the DB APIs directly to test the outcome on the tables in
the SQLite database.

The server tests spins up a local Flask instance as per
(https://flask.palletsprojects.com/en/stable/testing/#sending-requests-with-the-test-client)
and sends a request using the test client and we vet the request and response
produced by hitting said endpoint.

TODO:
  - Test that modifying the salt breaks verification
'''

import flask
import json
import nacl.signing
import os
import time
import werkzeug

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
    backend_key:        nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    master_key:         nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    rotating_key:       nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    creation_unix_ts_s: int                     = base.round_unix_ts_to_next_day(int(time.time()))
    class Scenario:
        payment_token_hash:      bytes                        = b''
        subscription_duration_s: int                          = 0
        proof:                   backend.ProSubscriptionProof = backend.ProSubscriptionProof()
        def __init__(self, payment_token_hash: bytes, subscription_duration_s: int):
            self.payment_token_hash      = payment_token_hash
            self.subscription_duration_s = subscription_duration_s

    scenarios: list[Scenario] = [
        Scenario(payment_token_hash=os.urandom(32), subscription_duration_s=30 * base.SECONDS_IN_DAY),
        Scenario(payment_token_hash=os.urandom(32), subscription_duration_s=365 * base.SECONDS_IN_DAY)
    ]

    for it in scenarios:
        # Verify unredeemed payments
        backend.add_unredeemed_payment(sql_conn=db.sql_conn,
                                       payment_token_hash=it.payment_token_hash,
                                       subscription_duration_s=it.subscription_duration_s,
                                       err=err)

        unredeemed_payment_list: list[backend.UnredeemedPaymentRow] = backend.get_unredeemed_payments_list(db.sql_conn)
        assert len(unredeemed_payment_list)                == 1
        unredeemed_payment_list[0].payment_token_hash      == it.payment_token_hash
        unredeemed_payment_list[0].subscription_duration_s == it.subscription_duration_s

        # Register the payment
        version: int = 0
        add_payment_hash: bytes = backend.make_payment_hash(version=version,
                                                            master_pkey=master_key.verify_key,
                                                            rotating_pkey=rotating_key.verify_key,
                                                            payment_token_hash=it.payment_token_hash)

        it.proof = backend.add_payment(version            = version,
                                       sql_conn           = db.sql_conn,
                                       signing_key        = backend_key,
                                       creation_unix_ts_s = creation_unix_ts_s,
                                       master_pkey        = master_key.verify_key,
                                       rotating_pkey      = rotating_key.verify_key,
                                       payment_token_hash = it.payment_token_hash,
                                       master_sig         = master_key.sign(add_payment_hash).signature,
                                       rotating_sig       = rotating_key.sign(add_payment_hash).signature,
                                       err                = err)
        assert it.proof.success, '{}'.format(err.msg_list)

        # Verify payment was redeemed
        unredeemed_payment_list = backend.get_unredeemed_payments_list(db.sql_conn)
        assert len(unredeemed_payment_list) == 0

    runtime: backend.RuntimeRow                     = backend.get_runtime(db.sql_conn)
    assert runtime.gen_index                       == 2

    user_list: list[backend.UserRow]                = backend.get_users_list(db.sql_conn)
    assert len(user_list)                          == 1
    assert user_list[0].master_pkey                == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(user_list[0].master_pkey.hex(), bytes(master_key.verify_key).hex())
    assert user_list[0].gen_index                  == runtime.gen_index - 1
    assert user_list[0].expiry_unix_ts_s           == creation_unix_ts_s + scenarios[0].subscription_duration_s + scenarios[1].subscription_duration_s + base.SECONDS_IN_DAY

    payment_list: list[backend.PaymentRow]          = backend.get_payments_list(db.sql_conn)
    assert len(payment_list)                       == 2
    assert payment_list[0].master_pkey             == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(payment_list[0].master_pkey.hex(), bytes(master_key.verify_key).hex())
    assert payment_list[0].subscription_duration_s == scenarios[0].subscription_duration_s
    assert payment_list[0].creation_unix_ts_s      == creation_unix_ts_s
    assert payment_list[0].activation_unix_ts_s    == creation_unix_ts_s
    assert payment_list[0].payment_token_hash      == scenarios[0].payment_token_hash

    assert payment_list[1].master_pkey             == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(payment_list[0].master_pkey.hex(), bytes(master_key.verify_key).hex())
    assert payment_list[1].subscription_duration_s == scenarios[1].subscription_duration_s
    assert payment_list[1].creation_unix_ts_s      == creation_unix_ts_s
    assert payment_list[1].activation_unix_ts_s    == None
    assert payment_list[1].payment_token_hash      == scenarios[1].payment_token_hash

    revocation_list: list[backend.RevocationRow]    = backend.get_revocations_list(db.sql_conn)
    assert len(revocation_list)                    == 1
    assert revocation_list[0].gen_index            == 0
    assert revocation_list[0].expiry_unix_ts_s     == creation_unix_ts_s + scenarios[0].subscription_duration_s + base.SECONDS_IN_DAY

    base.print_db_to_stdout(db.sql_conn)


def test_server_add_payment_flow():
    # Setup DB
    err                       = base.ErrorSink()
    db: backend.SetupDBResult = backend.setup_db(path='file:test_server_db?mode=memory&cache=shared', uri=True, err=err)
    assert len(err.msg_list) == 0, f'{err.msg_list}'
    assert db.sql_conn

    # Setup local flask instance
    flask_app:    flask.Flask     = server.init(testing_mode=True, db_path=db.path, db_path_is_uri=True)
    flask_client: werkzeug.Client = flask_app.test_client()

    # Register an unredeemed payment (by writing the the token to the DB directly)
    master_key             = nacl.signing.SigningKey.generate()
    rotating_key           = nacl.signing.SigningKey.generate()
    payment_token_hash     = os.urandom(32)
    backend.add_unredeemed_payment(sql_conn=db.sql_conn,
                                   payment_token_hash=payment_token_hash,
                                   subscription_duration_s=30 * base.SECONDS_IN_DAY,
                                   err=err)
    assert len(err.msg_list) == 0, f'{err.msg_list}'

    if 1: # Simulate client request to register a payment
        version: int = 0
        payment_hash_to_sign: bytes = backend.make_payment_hash(version=version,
                                                                master_pkey=master_key.verify_key,
                                                                rotating_pkey=rotating_key.verify_key,
                                                                payment_token_hash=payment_token_hash)

        response: werkzeug.test.TestResponse = flask_client.post(f'/{server.ROUTE_ADD_PAYMENT}', json={
            'version':       version,
            'master_pkey':   bytes(master_key.verify_key).hex(),
            'rotating_pkey': bytes(rotating_key.verify_key).hex(),
            'payment_token': payment_token_hash.hex(),
            'master_sig':    bytes(master_key.sign(payment_hash_to_sign).signature).hex(),
            'rotating_sig':  bytes(rotating_key.sign(payment_hash_to_sign).signature).hex(),
        })

        # Parse the JSON from the response
        response_json = response.get_json()
        assert isinstance(response_json, dict)

        # Parse status from response
        assert response_json['status'] == 200, f'Reponse was: {json.dumps(response_json, indent=2)}'

        # Parse result object is at root
        assert 'result' in response_json, f'Reponse was: {json.dumps(response_json, indent=2)}'
        result_json = response_json['result']

        # Extract the fields
        result_version:            int = base.dict_require(d=result_json, key='version',          default_val=0,  err_msg='Missing field', err=err)
        result_gen_index_hash_hex: str = base.dict_require(d=result_json, key='gen_index_hash',   default_val='', err_msg='Missing field', err=err)
        result_rotating_pkey_hex:  str = base.dict_require(d=result_json, key='rotating_pkey',    default_val='', err_msg='Missing field', err=err)
        result_expiry_unix_ts_s:   int = base.dict_require(d=result_json, key='expiry_unix_ts_s', default_val=0,  err_msg='Missing field', err=err)
        result_sig_hex:            str = base.dict_require(d=result_json, key='sig',              default_val='', err_msg='Missing field', err=err)
        assert len(err.msg_list) == 0, '{err.msg_list}'

        # Parse hex fields to bytes
        result_rotating_pkey         = nacl.signing.VerifyKey(base.hex_to_bytes(hex=result_rotating_pkey_hex, label='Rotating public key',   hex_len=64,  err=err))
        result_sig:            bytes =                        base.hex_to_bytes(hex=result_sig_hex,           label='Signature',             hex_len=128, err=err)
        result_gen_index_hash: bytes =                        base.hex_to_bytes(hex=result_gen_index_hash_hex,label='Generation index hash', hex_len=64,  err=err)
        assert len(err.msg_list) == 0, '{err.msg_list}'

        # Check the rotating key returned matches what we asked the server to sign
        assert result_rotating_pkey == rotating_key.verify_key

        # Check that the server signed our proof w/ their public key
        proof_hash: bytes = backend.make_pro_subscription_proof_hash(result_version,
                                                                     result_gen_index_hash,
                                                                     result_rotating_pkey,
                                                                     result_expiry_unix_ts_s)
        _ = db.runtime.backend_key.verify_key.verify(smessage=proof_hash, signature=result_sig)

    if 1: # Authorise a new rotated key for the pro subscription
        new_rotating_key    = nacl.signing.SigningKey.generate()
        version             = 0
        unix_ts_s           = int(time.time())
        hash_to_sign: bytes = backend.make_get_pro_subscription_proof_hash(version=version,
                                                                           master_pkey=master_key.verify_key,
                                                                           rotating_pkey=new_rotating_key.verify_key,
                                                                           unix_ts_s=unix_ts_s)

        response: werkzeug.test.TestResponse = flask_client.post(f'/{server.ROUTE_GET_PRO_SUBSCRIPTION_PROOF}', json={
            'version':       version,
            'master_pkey':   bytes(master_key.verify_key).hex(),
            'rotating_pkey': bytes(new_rotating_key.verify_key).hex(),
            'unix_ts_s':     unix_ts_s,
            'master_sig':    bytes(master_key.sign(hash_to_sign).signature).hex(),
            'rotating_sig':  bytes(new_rotating_key.sign(hash_to_sign).signature).hex(),
        })

        # Parse the JSON from the newly authorised key response
        response_json = response.get_json()
        assert isinstance(response_json, dict)

        # Parse status from response
        assert response_json['status'] == 200, f'Reponse was: {json.dumps(response_json, indent=2)}'

        # Parse result object is at root
        assert 'result' in response_json, f'Reponse was: {json.dumps(response_json, indent=2)}'
        result_json = response_json['result']

        # Extract the fields
        result_version:            int = base.dict_require(d=result_json, key='version',          default_val=0,  err_msg='Missing field', err=err)
        result_gen_index_hash_hex: str = base.dict_require(d=result_json, key='gen_index_hash',   default_val='', err_msg='Missing field', err=err)
        result_rotating_pkey_hex:  str = base.dict_require(d=result_json, key='rotating_pkey',    default_val='', err_msg='Missing field', err=err)
        result_expiry_unix_ts_s:   int = base.dict_require(d=result_json, key='expiry_unix_ts_s', default_val=0,  err_msg='Missing field', err=err)
        result_sig_hex:            str = base.dict_require(d=result_json, key='sig',              default_val='', err_msg='Missing field', err=err)
        assert len(err.msg_list) == 0, '{err.msg_list}'

        # Parse hex fields to bytes
        result_rotating_pkey  = nacl.signing.VerifyKey(base.hex_to_bytes(hex=result_rotating_pkey_hex, label='Rotating public key',   hex_len=64,  err=err))
        result_sig            =                        base.hex_to_bytes(hex=result_sig_hex,           label='Signature',             hex_len=128, err=err)
        result_gen_index_hash =                        base.hex_to_bytes(hex=result_gen_index_hash_hex,label='Generation index hash', hex_len=64,  err=err)
        assert len(err.msg_list) == 0, '{err.msg_list}'

        # Check the rotating key returned matches what we asked the server to sign
        assert result_rotating_pkey == new_rotating_key.verify_key

        # Check that the server signed our proof w/ their public key
        proof_hash = backend.make_pro_subscription_proof_hash(result_version,
                                                              result_gen_index_hash,
                                                              result_rotating_pkey,
                                                              result_expiry_unix_ts_s)
        _ = db.runtime.backend_key.verify_key.verify(smessage=proof_hash, signature=result_sig)
