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

import pprint
import flask
import json
import nacl.signing
import nacl.bindings
import nacl.public
import os
import time
import werkzeug
import dataclasses
import typing
import enum
import sqlite3
import traceback

import platform_google
from platform_google import handle_notification
import platform_google_api
from platform_google_types import GoogleDuration, SubscriptionProductDetails
from vendor import onion_req
import backend
import base
import server
import platform_apple

from appstoreserverlibrary.models.ResponseBodyV2DecodedPayload import ResponseBodyV2DecodedPayload as AppleResponseBodyV2DecodedPayload
from appstoreserverlibrary.models.JWSTransactionDecodedPayload import JWSTransactionDecodedPayload as AppleJWSTransactionDecodedPayload
from appstoreserverlibrary.models.JWSRenewalInfoDecodedPayload import JWSRenewalInfoDecodedPayload as AppleJWSRenewalInfoDecodedPayload
from appstoreserverlibrary.models.Data                         import Data                         as AppleData
from appstoreserverlibrary.models.Environment                  import Environment                  as AppleEnvironment
from appstoreserverlibrary.models.TransactionReason            import TransactionReason            as AppleTransactionReason
from appstoreserverlibrary.models.Type                         import Type                         as AppleType
from appstoreserverlibrary.models.Subtype                      import Subtype                      as AppleSubtype
from appstoreserverlibrary.models.Status                       import Status                       as AppleStatus
from appstoreserverlibrary.models.NotificationTypeV2           import NotificationTypeV2           as AppleNotificationTypeV2
from appstoreserverlibrary.models.InAppOwnershipType           import InAppOwnershipType           as AppleInAppOwnershipType

@dataclasses.dataclass
class TestingContext:
    """
    Sets up a database with the necessary tables and flask instance that you can simulate HTTP
    requests to, to target the Session Pro Backend routes. This class is designed to be used in a
    `with` context such that the DB is closed on scope exit.

    For tests, this means you probably want to supply a in-memory URI-style path to make a transient
    DB that is wiped on scope exit. This means tests have a fresh DB to work with for each `with`
    context and each chunk of tests to execute.
    """

    db:           backend.SetupDBResult
    sql_conn:     sqlite3.Connection
    flask_app:    flask.Flask
    flask_client: werkzeug.Client

    db_path:      str  = ''
    uri:          bool = False

    def __init__(self, db_path: str, uri: bool):
        self.db_path = db_path
        self.uri     = uri

    def __enter__(self):
        err     = base.ErrorSink()
        self.db = backend.setup_db(path=self.db_path, uri=self.uri, err=err)
        assert len(err.msg_list) == 0

        self.flask_app   = server.init(testing_mode=True,
                                       db_path=self.db_path,
                                       db_path_is_uri=self.uri,
                                       server_x25519_skey=self.db.runtime.backend_key.to_curve25519_private_key())
        self.flask_client = self.flask_app.test_client()
        assert self.db.sql_conn
        self.sql_conn = self.db.sql_conn
        return self

    def __exit__(self,
                 exc_type: object | None,
                 exc_value: object | None,
                 traceback: traceback.TracebackException | None):
        assert self.db.sql_conn
        self.db.sql_conn.close()
        self.sql_conn.close()
        return False

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
    unix_ts_ms:          int                     = int(time.time() * 1000)
    redeemed_unix_ts_ms: int                     = base.round_unix_ts_ms_to_next_day(unix_ts_ms)

    @dataclasses.dataclass
    class Scenario:
        google_payment_token:     str                          = ''
        google_order_id:          str                          = ''
        plan:                     base.ProPlan             = base.ProPlan.Nil
        proof:                    backend.ProSubscriptionProof = dataclasses.field(default_factory=backend.ProSubscriptionProof)
        payment_provider:         base.PaymentProvider         = base.PaymentProvider.Nil
        expiry_unix_ts_ms:        int                          = 0
        grace_period_duration_ms: int                          = 0

    scenarios: list[Scenario] = [
        Scenario(google_payment_token    = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
                 google_order_id         = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
                 plan                    = base.ProPlan.OneMonth,
                 expiry_unix_ts_ms       = redeemed_unix_ts_ms + ((30 * base.SECONDS_IN_DAY) * 1000),
                 grace_period_duration_ms        = 0,
                 payment_provider        = base.PaymentProvider.GooglePlayStore),

        Scenario(google_payment_token    = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
                 google_order_id         = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
                 plan                    = base.ProPlan.TwelveMonth,
                 expiry_unix_ts_ms       = redeemed_unix_ts_ms + ((31 * base.SECONDS_IN_DAY) * 1000),
                 grace_period_duration_ms        = 0,
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
                                       plan=it.plan,
                                       unredeemed_unix_ts_ms=unix_ts_ms,
                                       expiry_unix_ts_ms=it.expiry_unix_ts_ms,
                                       platform_refund_expiry_unix_ts_ms=0,
                                       err=err)
        assert len(err.msg_list) == 0

        unredeemed_payment_list: list[backend.PaymentRow] = backend.get_unredeemed_payments_list(db.sql_conn)
        assert len(unredeemed_payment_list)                       == 1
        assert unredeemed_payment_list[0].status                  == base.PaymentStatus.Unredeemed
        assert unredeemed_payment_list[0].payment_provider        == it.payment_provider
        assert unredeemed_payment_list[0].unredeemed_unix_ts_ms   == unix_ts_ms
        assert unredeemed_payment_list[0].redeemed_unix_ts_ms     == None
        assert unredeemed_payment_list[0].expiry_unix_ts_ms       == it.expiry_unix_ts_ms
        assert unredeemed_payment_list[0].revoked_unix_ts_ms      == None
        assert unredeemed_payment_list[0].google_payment_token    == it.google_payment_token
        assert unredeemed_payment_list[0].google_order_id         == it.google_order_id
        assert unredeemed_payment_list[0].plan                    == it.plan

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
    assert payment_list[0].plan                            == scenarios[0].plan
    assert payment_list[0].payment_provider                == scenarios[0].payment_provider
    assert payment_list[0].auto_renewing                   == True
    assert payment_list[0].redeemed_unix_ts_ms             == redeemed_unix_ts_ms
    assert payment_list[0].expiry_unix_ts_ms               == scenarios[0].expiry_unix_ts_ms
    assert payment_list[0].revoked_unix_ts_ms              is None
    assert payment_list[0].google_payment_token            == scenarios[0].google_payment_token
    assert len(payment_list[0].apple.tx_id)                == 0
    assert len(payment_list[0].apple.original_tx_id)       == 0
    assert len(payment_list[0].apple.web_line_order_tx_id) == 0

    assert payment_list[1].master_pkey                     == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(payment_list[0].master_pkey.hex(), bytes(master_key.verify_key).hex())
    assert payment_list[1].plan                            == scenarios[1].plan
    assert payment_list[1].payment_provider                == scenarios[1].payment_provider
    assert payment_list[1].auto_renewing                   == True
    assert payment_list[1].redeemed_unix_ts_ms             == redeemed_unix_ts_ms
    assert payment_list[1].expiry_unix_ts_ms               == scenarios[1].expiry_unix_ts_ms
    assert payment_list[1].revoked_unix_ts_ms              is None
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

    # NOTE: Update the latest payments grace period but set auto-renewing off
    payment_tx                                              = backend.PaymentProviderTransaction()
    payment_tx.provider                                     = scenarios[1].payment_provider
    payment_tx.google_payment_token                         = scenarios[1].google_payment_token
    payment_tx.google_order_id                              = scenarios[1].google_order_id
    new_grace_duration_ms                                   = 10000
    updated: bool                                           = backend.update_payment_renewal_info(sql_conn                 = db.sql_conn,
                                                                                                  payment_tx               = payment_tx,
                                                                                                  grace_period_duration_ms = new_grace_duration_ms,
                                                                                                  auto_renewing            = False,
                                                                                                  err                      = err)
    assert updated

    # NOTE: Verify that the new grace was assigned to the user
    payment_list: list[backend.PaymentRow]                  = backend.get_payments_list(db.sql_conn)
    assert len(payment_list)                               == 2
    assert payment_list[0].master_pkey                     == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(payment_list[0].master_pkey.hex(), bytes(master_key.verify_key).hex())
    assert payment_list[0].plan         == scenarios[0].plan
    assert payment_list[0].payment_provider                == scenarios[0].payment_provider
    assert payment_list[0].auto_renewing                   == True
    assert payment_list[0].redeemed_unix_ts_ms             == redeemed_unix_ts_ms
    assert payment_list[0].expiry_unix_ts_ms               == scenarios[0].expiry_unix_ts_ms
    assert payment_list[0].grace_period_duration_ms        == scenarios[0].grace_period_duration_ms
    assert payment_list[0].revoked_unix_ts_ms              is None
    assert payment_list[0].google_payment_token            == scenarios[0].google_payment_token
    assert len(payment_list[0].apple.tx_id)                == 0
    assert len(payment_list[0].apple.original_tx_id)       == 0
    assert len(payment_list[0].apple.web_line_order_tx_id) == 0

    assert payment_list[1].master_pkey                     == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(payment_list[0].master_pkey.hex(), bytes(master_key.verify_key).hex())
    assert payment_list[1].plan                            == scenarios[1].plan
    assert payment_list[1].payment_provider                == scenarios[1].payment_provider
    assert payment_list[1].auto_renewing                   == False
    assert payment_list[1].redeemed_unix_ts_ms             == redeemed_unix_ts_ms
    assert payment_list[1].expiry_unix_ts_ms               == scenarios[1].expiry_unix_ts_ms
    assert payment_list[1].grace_period_duration_ms        == new_grace_duration_ms
    assert payment_list[1].revoked_unix_ts_ms              is None
    assert payment_list[1].google_payment_token            == scenarios[1].google_payment_token
    assert len(payment_list[0].apple.tx_id)                == 0
    assert len(payment_list[0].apple.original_tx_id)       == 0
    assert len(payment_list[0].apple.web_line_order_tx_id) == 0

    # NOTE: Get the user and payments and verify that the expiry and grace are correct
    with base.SQLTransaction(db.sql_conn) as tx:
        get: backend.GetUserAndPayments = backend.get_user_and_payments(tx=tx, master_pkey=master_key.verify_key)
        assert get.auto_renewing            == False
        assert get.grace_period_duration_ms == new_grace_duration_ms

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
                                   plan=base.ProPlan.OneMonth,
                                   unredeemed_unix_ts_ms=unix_ts_ms,
                                   expiry_unix_ts_ms=next_day_unix_ts_ms + ((base.SECONDS_IN_DAY * 30) * 1000),
                                   platform_refund_expiry_unix_ts_ms=0,
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
                                                  endpoint=server.FLASK_ROUTE_GET_PRO_STATUS,
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
        result_items                               = base.json_dict_require_array(d=result_json, key='items',  err=err)
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
                                                  endpoint=server.FLASK_ROUTE_ADD_PRO_PAYMENT,
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
                                                  endpoint=server.FLASK_ROUTE_GET_PRO_PROOF,
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
                                       plan=base.ProPlan.OneMonth,
                                       unredeemed_unix_ts_ms=unix_ts_ms,
                                       expiry_unix_ts_ms=unix_ts_ms + ((base.SECONDS_IN_DAY * 30) * 1000),
                                       platform_refund_expiry_unix_ts_ms=0,
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
                                                  endpoint=server.FLASK_ROUTE_ADD_PRO_PAYMENT,
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
                                                  endpoint=server.FLASK_ROUTE_GET_PRO_REVOCATIONS,
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
        result_items                               = base.json_dict_require_array(d=result_json, key='items', err=err)
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
                                                  endpoint=server.FLASK_ROUTE_GET_PRO_REVOCATIONS,
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
        result_items = base.json_dict_require_array(d=result_json, key='items', err=err)
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
                                                  endpoint=server.FLASK_ROUTE_GET_PRO_STATUS,
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
        result_items = base.json_dict_require_array(d=result_json, key='items',  err=err)
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
                                                      endpoint=server.FLASK_ROUTE_GET_PRO_STATUS,
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
                                                      endpoint=server.FLASK_ROUTE_GET_PRO_STATUS,
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
                                                      endpoint=server.FLASK_ROUTE_GET_PRO_STATUS,
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
            result_items= base.json_dict_require_array(d=result_json, key='items',  err=err)
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

def print_python_decl_code_for_apple_obj(obj: object, indent_level: int = 0, var_name: str = None):
    class_name = obj.__class__.__name__

    # Initialize result string
    if var_name is None:
        var_name = class_name.lower()
    indent = " " * (indent_level * 4)
    result = f"{indent}{var_name} = Apple{class_name}()\n"

    # Get non-callable, non-private attributes
    attrs = {attr: getattr(obj, attr) for attr in dir(obj) if not attr.startswith('_') and not callable(getattr(obj, attr))}

    # Process each attribute
    for attr, value in attrs.items():
        if value is None:
            formatted_value = "None"
        elif isinstance(value, enum.Enum):
            formatted_value = f"Apple{value}"
        elif isinstance(value, str):
            formatted_value = f"'{value}'"
        elif isinstance(value, (int, float)):
            formatted_value = str(value)
        elif isinstance(value, bool):
            formatted_value = str(value).title()
        elif isinstance(value, (list, tuple, dict)):
            formatted_value = pprint.pformat(value)
        elif hasattr(value, '__dict__') or (hasattr(value, '__class__') and not isinstance(value, (int, str, float, bool, list, tuple, dict))):
            # Handle nested objects
            nested_var_name = f"{var_name}_{attr}"
            formatted_value = nested_var_name
            result += print_python_decl_code_for_apple_obj(value, indent_level, nested_var_name)
        else:
            # For enum-like objects or other complex types, try to preserve their full qualification
            formatted_value = str(value)
            if hasattr(value, '__module__') and value.__module__ != 'builtins':
                formatted_value = f"{value.__module__}.{formatted_value}"
        result += f"{indent}{var_name}.{attr:<35} = {formatted_value}\n"
    return result

def dump_apple_signed_payloads(core: platform_apple.Core, body: AppleResponseBodyV2DecodedPayload, prefix: str = ''):
    print("# NOTE: Generated by dump_apple_signed_payloads")
    print("# NOTE: Signed Payload")
    print(print_python_decl_code_for_apple_obj(body, 0, prefix + "body"))

    err = base.ErrorSink()
    decoded_notification = platform_apple.decoded_notification_from_apple_response_body_v2(body, core.signed_data_verifier, err)
    assert not err.has(), err.msg_list

    print("# NOTE: Signed Renewal Info")
    print(print_python_decl_code_for_apple_obj(decoded_notification.renewal_info, 0, prefix + 'renewal_info'))

    print("# NOTE: Signed Transaction Info")
    print(print_python_decl_code_for_apple_obj(decoded_notification.tx_info, 0, prefix + 'tx_info') + "\n")

    print(f'{prefix}decoded_notification = platform_apple.DecodedNotification(body={prefix}body, tx_info={prefix}tx_info, renewal_info={prefix}renewal_info)')
    print(f'platform_apple.handle_notification(decoded_notification={prefix}decoded_notification, sql_conn=db.sql_conn)')

def test_platform_apple():
    err = base.ErrorSink()

    # NOTE: Did renew notification
    with TestingContext(db_path='file:test_platform_apple_db?mode=memory&cache=shared', uri=True) as test:
        # NOTE: Original payload (requires keys to decrypt)
        if 0:
            core:                      platform_apple.Core       = platform_apple.init()
            notification_payload_json: dict[str, base.JSONValue] = json.loads('''
            {
              "signedPayload": "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJub3RpZmljYXRpb25UeXBlIjoiRElEX1JFTkVXIiwibm90aWZpY2F0aW9uVVVJRCI6IjFhN2NkYzNkLTkzNjAtNDljMy1hZTM3LTA0MjNlNGM2ZTdjNyIsImRhdGEiOnsiYXBwQXBwbGVJZCI6MTQ3MDE2ODg2OCwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwiYnVuZGxlVmVyc2lvbiI6IjYzNyIsImVudmlyb25tZW50IjoiU2FuZGJveCIsInNpZ25lZFRyYW5zYWN0aW9uSW5mbyI6ImV5SmhiR2NpT2lKRlV6STFOaUlzSW5nMVl5STZXeUpOU1VsRlRWUkRRMEUzWVdkQmQwbENRV2RKVVZJNFMwaDZaRzQxTlRSYUwxVnZjbUZrVG5nNWRIcEJTMEpuWjNGb2EycFBVRkZSUkVGNlFqRk5WVkYzVVdkWlJGWlJVVVJFUkhSQ1kwaENjMXBUUWxoaU0wcHpXa2hrY0ZwSFZXZFNSMVl5V2xkNGRtTkhWbmxKUmtwc1lrZEdNR0ZYT1hWamVVSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlV4TlFXdEhRVEZWUlVOM2QwTlNlbGw0UlhwQlVrSm5UbFpDUVc5TlEydEdkMk5IZUd4SlJXeDFXWGswZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOUWpSWVJGUkpNVTFFYTNoUFZFVTFUa1JSTVUxV2IxaEVWRWt6VFZSQmVFMTZSVE5PUkdONVRURnZkMmRhU1hoUlJFRXJRbWRPVmtKQlRVMU9NVUo1WWpKUloxSlZUa1JKUlRGb1dYbENRbU5JUVdkVk0xSjJZMjFWWjFsWE5XdEpSMnhWWkZjMWJHTjVRbFJrUnpsNVdsTkNVMXBYVG14aFdFSXdTVVpPY0ZveU5YQmliV040VEVSQmNVSm5UbFpDUVhOTlNUQkdkMk5IZUd4SlJtUjJZMjE0YTJReWJHdGFVMEpGV2xoYWJHSkhPWGRhV0VsblZXMVdjMWxZVW5CaU1qVjZUVkpOZDBWUldVUldVVkZMUkVGd1FtTklRbk5hVTBKS1ltMU5kVTFSYzNkRFVWbEVWbEZSUjBWM1NsWlZla0phVFVKTlIwSjVjVWRUVFRRNVFXZEZSME5EY1VkVFRUUTVRWGRGU0VFd1NVRkNUbTVXZG1oamRqZHBWQ3MzUlhnMWRFSk5RbWR5VVhOd1NIcEpjMWhTYVRCWmVHWmxhemRzZGpoM1JXMXFMMkpJYVZkMFRuZEtjV015UW05SWVuTlJhVVZxVURkTFJrbEpTMmMwV1RoNU1DOXVlVzUxUVcxcVoyZEpTVTFKU1VOQ1JFRk5RbWRPVmtoU1RVSkJaamhGUVdwQlFVMUNPRWRCTVZWa1NYZFJXVTFDWVVGR1JEaDJiRU5PVWpBeFJFcHRhV2M1TjJKQ09EVmpLMnhyUjB0YVRVaEJSME5EYzBkQlVWVkdRbmRGUWtKSFVYZFpha0YwUW1kbmNrSm5SVVpDVVdOM1FXOVphR0ZJVWpCalJHOTJUREpPYkdOdVVucE1iVVozWTBkNGJFeHRUblppVXprelpESlNlVnA2V1hWYVIxWjVUVVJGUjBORGMwZEJVVlZHUW5wQlFtaHBWbTlrU0ZKM1QyazRkbUl5VG5walF6Vm9ZMGhDYzFwVE5XcGlNakIyWWpKT2VtTkVRWHBNV0dReldraEtiazVxUVhsTlNVbENTR2RaUkZaU01HZENTVWxDUmxSRFEwRlNSWGRuWjBWT1FtZHZjV2hyYVVjNU1rNXJRbEZaUWsxSlNDdE5TVWhFUW1kbmNrSm5SVVpDVVdORFFXcERRblJuZVVKek1VcHNZa2RzYUdKdFRteEpSemwxU1VoU2IyRllUV2RaTWxaNVpFZHNiV0ZYVG1oa1IxVm5XVzVyWjFsWE5UVkpTRUpvWTI1U05VbEhSbnBqTTFaMFdsaE5aMWxYVG1wYVdFSXdXVmMxYWxwVFFuWmFhVUl3WVVkVloyUkhhR3hpYVVKb1kwaENjMkZYVG1oWmJYaHNTVWhPTUZsWE5XdFpXRXByU1VoU2JHTnRNWHBKUjBaMVdrTkNhbUl5Tld0aFdGSndZakkxZWtsSE9XMUpTRlo2V2xOM1oxa3lWbmxrUjJ4dFlWZE9hR1JIVldkalJ6bHpZVmRPTlVsSFJuVmFRMEpxV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxJUW5sWlYwNHdZVmRPYkVsSVRqQlpXRkpzWWxkV2RXUklUWFZOUkZsSFEwTnpSMEZSVlVaQ2QwbENSbWx3YjJSSVVuZFBhVGgyWkROa00weHRSbmRqUjNoc1RHMU9kbUpUT1dwYVdFb3dZVmRhY0ZreVJqQmFWMFl4WkVkb2RtTnRiREJsVXpoM1NGRlpSRlpTTUU5Q1FsbEZSa2xHYVc5SE5IZE5UVlpCTVd0MU9YcEtiVWRPVUVGV2JqTmxjVTFCTkVkQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlVVSm5iM0ZvYTJsSE9USk9hMEpuYzBKQ1FVbEdRVVJCUzBKblozRm9hMnBQVUZGUlJFRjNUbkJCUkVKdFFXcEZRU3R4V0c1U1JVTTNhRmhKVjFaTWMweDRlbTVxVW5CSmVsQm1OMVpJZWpsV0wwTlViVGdyVEVwc2NsRmxjRzV0WTFCMlIweE9ZMWcyV0ZCdWJHTm5URUZCYWtWQk5VbHFUbHBMWjJjMWNGRTNPV3R1UmpSSllsUllaRXQyT0haMWRFbEVUVmhFYldwUVZsUXpaRWQyUm5SelIxSjNXRTk1ZDFJeWExcERaRk55Wm1WdmRDSXNJazFKU1VSR2FrTkRRWEI1WjBGM1NVSkJaMGxWU1hOSGFGSjNjREJqTW01MlZUUlpVM2xqWVdaUVZHcDZZazVqZDBObldVbExiMXBKZW1vd1JVRjNUWGRhZWtWaVRVSnJSMEV4VlVWQmQzZFRVVmhDZDJKSFZXZFZiVGwyWkVOQ1JGRlRRWFJKUldONlRWTlpkMHBCV1VSV1VWRk1SRUl4UW1OSVFuTmFVMEpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJWUk5Ra1ZIUVRGVlJVTm5kMHRSV0VKM1lrZFZaMU5YTldwTWFrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmQwaG9ZMDVOYWtWM1RYcEZNMDFxUVhwT2VrVjNWMmhqVGsxNldYZE5la1UxVFVSQmQwMUVRWGRYYWtJeFRWVlJkMUZuV1VSV1VWRkVSRVIwUW1OSVFuTmFVMEpZWWpOS2MxcElaSEJhUjFWblVrZFdNbHBYZUhaalIxWjVTVVpLYkdKSFJqQmhWemwxWTNsQ1JGcFlTakJoVjFwd1dUSkdNR0ZYT1hWSlJVWXhaRWRvZG1OdGJEQmxWRVZNVFVGclIwRXhWVVZEZDNkRFVucFplRVY2UVZKQ1owNVdRa0Z2VFVOclJuZGpSM2hzU1VWc2RWbDVOSGhEZWtGS1FtZE9Wa0pCV1ZSQmJGWlVUVWhaZDBWQldVaExiMXBKZW1vd1EwRlJXVVpMTkVWRlFVTkpSRmxuUVVWaWMxRkxRemswVUhKc1YyMWFXRzVZWjNSNGVtUldTa3c0VkRCVFIxbHVaMFJTUjNCdVoyNHpUalpRVkRoS1RVVmlOMFpFYVRSaVFtMVFhRU51V2pNdmMzRTJVRVl2WTBkalMxaFhjMHcxZGs5MFpWSm9lVW8wTlhnelFWTlFOMk5QUWl0aFlXODVNR1pqY0hoVGRpOUZXa1ppYm1sQllrNW5Xa2RvU1dod1NXODBTRFpOU1VnelRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaamhEUVZGQmQwaDNXVVJXVWpCcVFrSm5kMFp2UVZWMU4wUmxiMVpuZW1sS2NXdHBjRzVsZG5JemNuSTVja3hLUzNOM1VtZFpTVXQzV1VKQ1VWVklRVkZGUlU5cVFUUk5SRmxIUTBOelIwRlJWVVpDZWtGQ2FHbHdiMlJJVW5kUGFUaDJZakpPZW1ORE5XaGpTRUp6V2xNMWFtSXlNSFppTWs1NlkwUkJla3hYUm5kalIzaHNZMjA1ZG1SSFRtaGFlazEzVG5kWlJGWlNNR1pDUkVGM1RHcEJjMjlEY1dkTFNWbHRZVWhTTUdORWIzWk1NazU1WWtNMWFHTklRbk5hVXpWcVlqSXdkbGxZUW5kaVIxWjVZakk1TUZreVJtNU5lVFZxWTIxM2QwaFJXVVJXVWpCUFFrSlpSVVpFT0hac1EwNVNNREZFU20xcFp6azNZa0k0TldNcmJHdEhTMXBOUVRSSFFURlZaRVIzUlVJdmQxRkZRWGRKUWtKcVFWRkNaMjl4YUd0cFJ6a3lUbXRDWjBsQ1FrRkpSa0ZFUVV0Q1oyZHhhR3RxVDFCUlVVUkJkMDV2UVVSQ2JFRnFRa0ZZYUZOeE5VbDVTMjluVFVOUWRIYzBPVEJDWVVJMk56ZERZVVZIU2xoMVpsRkNMMFZ4V2tka05rTlRhbWxEZEU5dWRVMVVZbGhXV0cxNGVHTjRabXREVFZGRVZGTlFlR0Z5V2xoMlRuSnJlRlV6Vkd0VlRVa3pNM2w2ZGtaV1ZsSlVOSGQ0VjBwRE9UazBUM05rWTFvMEsxSkhUbk5aUkhsU05XZHRaSEl3YmtSSFp6MGlMQ0pOU1VsRFVYcERRMEZqYldkQmQwbENRV2RKU1V4aldEaHBUa3hHVXpWVmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhkYWVrVmlUVUpyUjBFeFZVVkJkM2RUVVZoQ2QySkhWV2RWYlRsMlpFTkNSRkZUUVhSSlJXTjZUVk5aZDBwQldVUldVVkZNUkVJeFFtTklRbk5hVTBKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVlJOUWtWSFFURlZSVU5uZDB0UldFSjNZa2RWWjFOWE5XcE1ha1ZNVFVGclIwRXhWVVZDYUUxRFZsWk5kMGhvWTA1TlZGRjNUa1JOZDAxVVozaFBWRUV5VjJoalRrMTZhM2RPUkUxM1RWUm5lRTlVUVRKWGFrSnVUVkp6ZDBkUldVUldVVkZFUkVKS1FtTklRbk5hVTBKVFlqSTVNRWxGVGtKSlF6Qm5VbnBOZUVwcVFXdENaMDVXUWtGelRVaFZSbmRqUjNoc1NVVk9iR051VW5CYWJXeHFXVmhTY0dJeU5HZFJXRll3WVVjNWVXRllValZOVWsxM1JWRlpSRlpSVVV0RVFYQkNZMGhDYzFwVFFrcGliVTExVFZGemQwTlJXVVJXVVZGSFJYZEtWbFY2UWpKTlFrRkhRbmx4UjFOTk5EbEJaMFZIUWxOMVFrSkJRV2xCTWtsQlFrcHFjRXg2TVVGamNWUjBhM2xLZVdkU1RXTXpVa05XT0dOWGFsUnVTR05HUW1KYVJIVlhiVUpUY0ROYVNIUm1WR3BxVkhWNGVFVjBXQzh4U0RkWmVWbHNNMG8yV1ZKaVZIcENVRVZXYjBFdlZtaFpSRXRZTVVSNWVFNUNNR05VWkdSeFdHdzFaSFpOVm5wMFN6VXhOMGxFZGxsMVZsUmFXSEJ0YTA5c1JVdE5ZVTVEVFVWQmQwaFJXVVJXVWpCUFFrSlpSVVpNZFhjemNVWlpUVFJwWVhCSmNWb3pjalk1TmpZdllYbDVVM0pOUVRoSFFURlZaRVYzUlVJdmQxRkdUVUZOUWtGbU9IZEVaMWxFVmxJd1VFRlJTQzlDUVZGRVFXZEZSMDFCYjBkRFEzRkhVMDAwT1VKQlRVUkJNbWRCVFVkVlEwMVJRMFEyWTBoRlJtdzBZVmhVVVZreVpUTjJPVWQzVDBGRldreDFUaXQ1VW1oSVJrUXZNMjFsYjNsb2NHMTJUM2RuVUZWdVVGZFVlRzVUTkdGMEszRkplRlZEVFVjeGJXbG9SRXN4UVROVlZEZ3lUbEY2TmpCcGJVOXNUVEkzYW1Ka2IxaDBNbEZtZVVaTmJTdFphR2xrUkd0TVJqRjJURlZoWjAwMlFtZEVOVFpMZVV0QlBUMGlYWDAuZXlKMGNtRnVjMkZqZEdsdmJrbGtJam9pTWpBd01EQXdNVEF5TkRrNU9EazFOQ0lzSW05eWFXZHBibUZzVkhKaGJuTmhZM1JwYjI1SlpDSTZJakl3TURBd01ERXdNalE1T1RNeU9Ua2lMQ0ozWldKUGNtUmxja3hwYm1WSmRHVnRTV1FpT2lJeU1EQXdNREF3TVRFek56VTFORFl4SWl3aVluVnVaR3hsU1dRaU9pSmpiMjB1Ykc5cmFTMXdjbTlxWldOMExteHZhMmt0YldWemMyVnVaMlZ5SWl3aWNISnZaSFZqZEVsa0lqb2lZMjl0TG1kbGRITmxjM05wYjI0dWIzSm5MbkJ5YjE5emRXSWlMQ0p6ZFdKelkzSnBjSFJwYjI1SGNtOTFjRWxrWlc1MGFXWnBaWElpT2lJeU1UYzFNamd4TkNJc0luQjFjbU5vWVhObFJHRjBaU0k2TVRjMU9UTXdNalUxTWpBd01Dd2liM0pwWjJsdVlXeFFkWEpqYUdGelpVUmhkR1VpT2pFM05Ua3pNREU0TXpNd01EQXNJbVY0Y0dseVpYTkVZWFJsSWpveE56VTVNekF5TnpNeU1EQXdMQ0p4ZFdGdWRHbDBlU0k2TVN3aWRIbHdaU0k2SWtGMWRHOHRVbVZ1WlhkaFlteGxJRk4xWW5OamNtbHdkR2x2YmlJc0ltbHVRWEJ3VDNkdVpYSnphR2x3Vkhsd1pTSTZJbEJWVWtOSVFWTkZSQ0lzSW5OcFoyNWxaRVJoZEdVaU9qRTNOVGt6TURJMU1UZzRNelVzSW1WdWRtbHliMjV0Wlc1MElqb2lVMkZ1WkdKdmVDSXNJblJ5WVc1ellXTjBhVzl1VW1WaGMyOXVJam9pVWtWT1JWZEJUQ0lzSW5OMGIzSmxabkp2Ym5RaU9pSkJWVk1pTENKemRHOXlaV1p5YjI1MFNXUWlPaUl4TkRNME5qQWlMQ0p3Y21salpTSTZNVGs1TUN3aVkzVnljbVZ1WTNraU9pSkJWVVFpTENKaGNIQlVjbUZ1YzJGamRHbHZia2xrSWpvaU56QTBPRGszTkRZNU9UQXpNemd6T1RFNUluMC56NlJBSThxMDFzd1RoVmVFZzlQS1FrNHNKTzVKc1RRV0FibjhWcFdFNDRPRXBFZ1FWNTlhcTRQNFdYaHZDYU9mdkh6WHotbmxINnZPNUNUaDVaTEN5dyIsInNpZ25lZFJlbmV3YWxJbmZvIjoiZXlKaGJHY2lPaUpGVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxGVFZSRFEwRTNZV2RCZDBsQ1FXZEpVVkk0UzBoNlpHNDFOVFJhTDFWdmNtRmtUbmc1ZEhwQlMwSm5aM0ZvYTJwUFVGRlJSRUY2UWpGTlZWRjNVV2RaUkZaUlVVUkVSSFJDWTBoQ2MxcFRRbGhpTTBweldraGtjRnBIVldkU1IxWXlXbGQ0ZG1OSFZubEpSa3BzWWtkR01HRlhPWFZqZVVKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVXhOUVd0SFFURlZSVU4zZDBOU2VsbDRSWHBCVWtKblRsWkNRVzlOUTJ0R2QyTkhlR3hKUld4MVdYazBlRU42UVVwQ1owNVdRa0ZaVkVGc1ZsUk5RalJZUkZSSk1VMUVhM2hQVkVVMVRrUlJNVTFXYjFoRVZFa3pUVlJCZUUxNlJUTk9SR041VFRGdmQyZGFTWGhSUkVFclFtZE9Wa0pCVFUxT01VSjVZakpSWjFKVlRrUkpSVEZvV1hsQ1FtTklRV2RWTTFKMlkyMVZaMWxYTld0SlIyeFZaRmMxYkdONVFsUmtSemw1V2xOQ1UxcFhUbXhoV0VJd1NVWk9jRm95TlhCaWJXTjRURVJCY1VKblRsWkNRWE5OU1RCR2QyTkhlR3hKUm1SMlkyMTRhMlF5Ykd0YVUwSkZXbGhhYkdKSE9YZGFXRWxuVlcxV2MxbFlVbkJpTWpWNlRWSk5kMFZSV1VSV1VWRkxSRUZ3UW1OSVFuTmFVMEpLWW0xTmRVMVJjM2REVVZsRVZsRlJSMFYzU2xaVmVrSmFUVUpOUjBKNWNVZFRUVFE1UVdkRlIwTkRjVWRUVFRRNVFYZEZTRUV3U1VGQ1RtNVdkbWhqZGpkcFZDczNSWGcxZEVKTlFtZHlVWE53U0hwSmMxaFNhVEJaZUdabGF6ZHNkamgzUlcxcUwySklhVmQwVG5kS2NXTXlRbTlJZW5OUmFVVnFVRGRMUmtsSlMyYzBXVGg1TUM5dWVXNTFRVzFxWjJkSlNVMUpTVU5DUkVGTlFtZE9Wa2hTVFVKQlpqaEZRV3BCUVUxQ09FZEJNVlZrU1hkUldVMUNZVUZHUkRoMmJFTk9VakF4UkVwdGFXYzVOMkpDT0RWaksyeHJSMHRhVFVoQlIwTkRjMGRCVVZWR1FuZEZRa0pIVVhkWmFrRjBRbWRuY2tKblJVWkNVV04zUVc5WmFHRklVakJqUkc5MlRESk9iR051VW5wTWJVWjNZMGQ0YkV4dFRuWmlVemt6WkRKU2VWcDZXWFZhUjFaNVRVUkZSME5EYzBkQlVWVkdRbnBCUW1ocFZtOWtTRkozVDJrNGRtSXlUbnBqUXpWb1kwaENjMXBUTldwaU1qQjJZakpPZW1ORVFYcE1XR1F6V2toS2JrNXFRWGxOU1VsQ1NHZFpSRlpTTUdkQ1NVbENSbFJEUTBGU1JYZG5aMFZPUW1kdmNXaHJhVWM1TWs1clFsRlpRazFKU0N0TlNVaEVRbWRuY2tKblJVWkNVV05EUVdwRFFuUm5lVUp6TVVwc1lrZHNhR0p0VG14SlJ6bDFTVWhTYjJGWVRXZFpNbFo1WkVkc2JXRlhUbWhrUjFWbldXNXJaMWxYTlRWSlNFSm9ZMjVTTlVsSFJucGpNMVowV2xoTloxbFhUbXBhV0VJd1dWYzFhbHBUUW5aYWFVSXdZVWRWWjJSSGFHeGlhVUpvWTBoQ2MyRlhUbWhaYlhoc1NVaE9NRmxYTld0WldFcHJTVWhTYkdOdE1YcEpSMFoxV2tOQ2FtSXlOV3RoV0ZKd1lqSTFla2xIT1cxSlNGWjZXbE4zWjFreVZubGtSMnh0WVZkT2FHUkhWV2RqUnpsellWZE9OVWxIUm5WYVEwSnFXbGhLTUdGWFduQlpNa1l3WVZjNWRVbElRbmxaVjA0d1lWZE9iRWxJVGpCWldGSnNZbGRXZFdSSVRYVk5SRmxIUTBOelIwRlJWVVpDZDBsQ1JtbHdiMlJJVW5kUGFUaDJaRE5rTTB4dFJuZGpSM2hzVEcxT2RtSlRPV3BhV0Vvd1lWZGFjRmt5UmpCYVYwWXhaRWRvZG1OdGJEQmxVemgzU0ZGWlJGWlNNRTlDUWxsRlJrbEdhVzlITkhkTlRWWkJNV3QxT1hwS2JVZE9VRUZXYmpObGNVMUJORWRCTVZWa1JIZEZRaTkzVVVWQmQwbElaMFJCVVVKbmIzRm9hMmxIT1RKT2EwSm5jMEpDUVVsR1FVUkJTMEpuWjNGb2EycFBVRkZSUkVGM1RuQkJSRUp0UVdwRlFTdHhXRzVTUlVNM2FGaEpWMVpNYzB4NGVtNXFVbkJKZWxCbU4xWkllamxXTDBOVWJUZ3JURXBzY2xGbGNHNXRZMUIyUjB4T1kxZzJXRkJ1YkdOblRFRkJha1ZCTlVscVRscExaMmMxY0ZFM09XdHVSalJKWWxSWVpFdDJPSFoxZEVsRVRWaEViV3BRVmxRelpFZDJSblJ6UjFKM1dFOTVkMUl5YTFwRFpGTnlabVZ2ZENJc0lrMUpTVVJHYWtORFFYQjVaMEYzU1VKQlowbFZTWE5IYUZKM2NEQmpNbTUyVlRSWlUzbGpZV1pRVkdwNllrNWpkME5uV1VsTGIxcEplbW93UlVGM1RYZGFla1ZpVFVKclIwRXhWVVZCZDNkVFVWaENkMkpIVldkVmJUbDJaRU5DUkZGVFFYUkpSV042VFZOWmQwcEJXVVJXVVZGTVJFSXhRbU5JUW5OYVUwSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlZSTlFrVkhRVEZWUlVObmQwdFJXRUozWWtkVloxTlhOV3BNYWtWTVRVRnJSMEV4VlVWQ2FFMURWbFpOZDBob1kwNU5ha1YzVFhwRk0wMXFRWHBPZWtWM1YyaGpUazE2V1hkTmVrVTFUVVJCZDAxRVFYZFhha0l4VFZWUmQxRm5XVVJXVVZGRVJFUjBRbU5JUW5OYVUwSllZak5LYzFwSVpIQmFSMVZuVWtkV01scFhlSFpqUjFaNVNVWktiR0pIUmpCaFZ6bDFZM2xDUkZwWVNqQmhWMXB3V1RKR01HRlhPWFZKUlVZeFpFZG9kbU50YkRCbFZFVk1UVUZyUjBFeFZVVkRkM2REVW5wWmVFVjZRVkpDWjA1V1FrRnZUVU5yUm5kalIzaHNTVVZzZFZsNU5IaERla0ZLUW1kT1ZrSkJXVlJCYkZaVVRVaFpkMFZCV1VoTGIxcEplbW93UTBGUldVWkxORVZGUVVOSlJGbG5RVVZpYzFGTFF6azBVSEpzVjIxYVdHNVlaM1I0ZW1SV1NrdzRWREJUUjFsdVowUlNSM0J1WjI0elRqWlFWRGhLVFVWaU4wWkVhVFJpUW0xUWFFTnVXak12YzNFMlVFWXZZMGRqUzFoWGMwdzFkazkwWlZKb2VVbzBOWGd6UVZOUU4yTlBRaXRoWVc4NU1HWmpjSGhUZGk5RldrWmlibWxCWWs1bldrZG9TV2h3U1c4MFNEWk5TVWd6VFVKSlIwRXhWV1JGZDBWQ0wzZFJTVTFCV1VKQlpqaERRVkZCZDBoM1dVUldVakJxUWtKbmQwWnZRVlYxTjBSbGIxWm5lbWxLY1d0cGNHNWxkbkl6Y25JNWNreEtTM04zVW1kWlNVdDNXVUpDVVZWSVFWRkZSVTlxUVRSTlJGbEhRME56UjBGUlZVWkNla0ZDYUdsd2IyUklVbmRQYVRoMllqSk9lbU5ETldoalNFSnpXbE0xYW1JeU1IWmlNazU2WTBSQmVreFhSbmRqUjNoc1kyMDVkbVJIVG1oYWVrMTNUbmRaUkZaU01HWkNSRUYzVEdwQmMyOURjV2RMU1ZsdFlVaFNNR05FYjNaTU1rNTVZa00xYUdOSVFuTmFVelZxWWpJd2RsbFlRbmRpUjFaNVlqSTVNRmt5Um01TmVUVnFZMjEzZDBoUldVUldVakJQUWtKWlJVWkVPSFpzUTA1U01ERkVTbTFwWnprM1lrSTROV01yYkd0SFMxcE5RVFJIUVRGVlpFUjNSVUl2ZDFGRlFYZEpRa0pxUVZGQ1oyOXhhR3RwUnpreVRtdENaMGxDUWtGSlJrRkVRVXRDWjJkeGFHdHFUMUJSVVVSQmQwNXZRVVJDYkVGcVFrRllhRk54TlVsNVMyOW5UVU5RZEhjME9UQkNZVUkyTnpkRFlVVkhTbGgxWmxGQ0wwVnhXa2RrTmtOVGFtbERkRTl1ZFUxVVlsaFdXRzE0ZUdONFptdERUVkZFVkZOUWVHRnlXbGgyVG5KcmVGVXpWR3RWVFVrek0zbDZka1pXVmxKVU5IZDRWMHBET1RrMFQzTmtZMW8wSzFKSFRuTlpSSGxTTldkdFpISXdia1JIWnowaUxDSk5TVWxEVVhwRFEwRmpiV2RCZDBsQ1FXZEpTVXhqV0RocFRreEdVelZWZDBObldVbExiMXBKZW1vd1JVRjNUWGRhZWtWaVRVSnJSMEV4VlVWQmQzZFRVVmhDZDJKSFZXZFZiVGwyWkVOQ1JGRlRRWFJKUldONlRWTlpkMHBCV1VSV1VWRk1SRUl4UW1OSVFuTmFVMEpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJWUk5Ra1ZIUVRGVlJVTm5kMHRSV0VKM1lrZFZaMU5YTldwTWFrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmQwaG9ZMDVOVkZGM1RrUk5kMDFVWjNoUFZFRXlWMmhqVGsxNmEzZE9SRTEzVFZSbmVFOVVRVEpYYWtKdVRWSnpkMGRSV1VSV1VWRkVSRUpLUW1OSVFuTmFVMEpUWWpJNU1FbEZUa0pKUXpCblVucE5lRXBxUVd0Q1owNVdRa0Z6VFVoVlJuZGpSM2hzU1VWT2JHTnVVbkJhYld4cVdWaFNjR0l5TkdkUldGWXdZVWM1ZVdGWVVqVk5VazEzUlZGWlJGWlJVVXRFUVhCQ1kwaENjMXBUUWtwaWJVMTFUVkZ6ZDBOUldVUldVVkZIUlhkS1ZsVjZRakpOUWtGSFFubHhSMU5OTkRsQlowVkhRbE4xUWtKQlFXbEJNa2xCUWtwcWNFeDZNVUZqY1ZSMGEzbEtlV2RTVFdNelVrTldPR05YYWxSdVNHTkdRbUphUkhWWGJVSlRjRE5hU0hSbVZHcHFWSFY0ZUVWMFdDOHhTRGRaZVZsc00wbzJXVkppVkhwQ1VFVldiMEV2Vm1oWlJFdFlNVVI1ZUU1Q01HTlVaR1J4V0d3MVpIWk5WbnAwU3pVeE4wbEVkbGwxVmxSYVdIQnRhMDlzUlV0TllVNURUVVZCZDBoUldVUldVakJQUWtKWlJVWk1kWGN6Y1VaWlRUUnBZWEJKY1ZvemNqWTVOall2WVhsNVUzSk5RVGhIUVRGVlpFVjNSVUl2ZDFGR1RVRk5Ra0ZtT0hkRVoxbEVWbEl3VUVGUlNDOUNRVkZFUVdkRlIwMUJiMGREUTNGSFUwMDBPVUpCVFVSQk1tZEJUVWRWUTAxUlEwUTJZMGhGUm13MFlWaFVVVmt5WlROMk9VZDNUMEZGV2t4MVRpdDVVbWhJUmtRdk0yMWxiM2xvY0cxMlQzZG5VRlZ1VUZkVWVHNVROR0YwSzNGSmVGVkRUVWN4Yldsb1JFc3hRVE5WVkRneVRsRjZOakJwYlU5c1RUSTNhbUprYjFoME1sRm1lVVpOYlN0WmFHbGtSR3RNUmpGMlRGVmhaMDAyUW1kRU5UWkxlVXRCUFQwaVhYMC5leUp2Y21sbmFXNWhiRlJ5WVc1ellXTjBhVzl1U1dRaU9pSXlNREF3TURBeE1ESTBPVGt6TWprNUlpd2lZWFYwYjFKbGJtVjNVSEp2WkhWamRFbGtJam9pWTI5dExtZGxkSE5sYzNOcGIyNHViM0puTG5CeWIxOXpkV0lpTENKd2NtOWtkV04wU1dRaU9pSmpiMjB1WjJWMGMyVnpjMmx2Ymk1dmNtY3VjSEp2WDNOMVlpSXNJbUYxZEc5U1pXNWxkMU4wWVhSMWN5STZNU3dpY21WdVpYZGhiRkJ5YVdObElqb3hPVGt3TENKamRYSnlaVzVqZVNJNklrRlZSQ0lzSW5OcFoyNWxaRVJoZEdVaU9qRTNOVGt6TURJMU1UZzRNelVzSW1WdWRtbHliMjV0Wlc1MElqb2lVMkZ1WkdKdmVDSXNJbkpsWTJWdWRGTjFZbk5qY21sd2RHbHZibE4wWVhKMFJHRjBaU0k2TVRjMU9UTXdNVGd6TWpBd01Dd2ljbVZ1WlhkaGJFUmhkR1VpT2pFM05Ua3pNREkzTXpJd01EQXNJbUZ3Y0ZSeVlXNXpZV04wYVc5dVNXUWlPaUkzTURRNE9UYzBOams1TURNek9ETTVNVGtpZlEuUFRCY0ZYUy1Oa1Zpa01vLXJoajdiUWZEbDNpT0tLRTZvRkw0LURiZFdLeFUxWGJrQ2VCRGc5dlBSZUgyZWJabmtic2o2Z3F1NjFWTmVRb2pwV0ZFdWciLCJzdGF0dXMiOjF9LCJ2ZXJzaW9uIjoiMi4wIiwic2lnbmVkRGF0ZSI6MTc1OTMwMjUxODgzNX0.2HnJDUBk2klLBZao8VmbekkHKkONr26rcW3I6Uoqa4o6JfnduiVoTbZWzPGoNabmz94Dt8RycMQadlJkXdnYDQ"
            }
            ''')

            signed_payload: str                               = typing.cast(str, notification_payload_json['signedPayload'])
            body:           AppleResponseBodyV2DecodedPayload = core.signed_data_verifier.verify_and_decode_notification(signed_payload)

        # NOTE: Generate by constructing object from dump_apple_signed_payload()
        body = AppleResponseBodyV2DecodedPayload()
        body.data = AppleData(environment=AppleEnvironment.SANDBOX,
                              rawEnvironment              = 'Sandbox',
                              appAppleId                  = 1470168868,
                              bundleId                    = 'com.loki-project.loki-messenger',
                              bundleVersion               = '637',
                              signedTransactionInfo       = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNDk5ODk1NCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTEzNzU1NDYxIiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTMwMjU1MjAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5MzAyNzMyMDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTkzMDI1MTg4MzUsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUkVORVdBTCIsInN0b3JlZnJvbnQiOiJBVVMiLCJzdG9yZWZyb250SWQiOiIxNDM0NjAiLCJwcmljZSI6MTk5MCwiY3VycmVuY3kiOiJBVUQiLCJhcHBUcmFuc2FjdGlvbklkIjoiNzA0ODk3NDY5OTAzMzgzOTE5In0.z6RAI8q01swThVeEg9PKQk4sJO5JsTQWAbn8VpWE44OEpEgQV59aq4P4WXhvCaOfvHzXz-nlH6vO5CTh5ZLCyw',
                              signedRenewalInfo           = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MSwicmVuZXdhbFByaWNlIjoxOTkwLCJjdXJyZW5jeSI6IkFVRCIsInNpZ25lZERhdGUiOjE3NTkzMDI1MTg4MzUsImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc1OTMwMTgzMjAwMCwicmVuZXdhbERhdGUiOjE3NTkzMDI3MzIwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.PTBcFXS-NkVikMo-rhj7bQfDl3iOKKE6oFL4-DbdWKxU1XbkCeBDg9vPReH2ebZnkbsj6gqu61VNeQojpWFEug',
                              status                      = AppleStatus.ACTIVE,
                              rawStatus                   = 1,
                              consumptionRequestReason    = None,
                              rawConsumptionRequestReason = None)
        body.externalPurchaseToken               = None
        body.notificationType                    = AppleNotificationTypeV2.DID_RENEW
        body.notificationUUID                    = '1a7cdc3d-9360-49c3-ae37-0423e4c6e7c7'
        body.rawNotificationType                 = 'DID_RENEW'
        body.rawSubtype                          = None
        body.signedDate                          = 1759302518835
        body.subtype                             = None
        body.summary                             = None
        body.version                             = '2.0'

        renewal_info                             = AppleJWSRenewalInfoDecodedPayload()
        renewal_info.appAccountToken             = None
        renewal_info.appTransactionId            = '704897469903383919'
        renewal_info.autoRenewProductId          = None
        renewal_info.autoRenewStatus             = None
        renewal_info.currency                    = 'AUD'
        renewal_info.eligibleWinBackOfferIds     = None
        renewal_info.environment                 = AppleEnvironment.SANDBOX
        renewal_info.expirationIntent            = None
        renewal_info.gracePeriodExpiresDate      = None
        renewal_info.isInBillingRetryPeriod      = None
        renewal_info.offerDiscountType           = None
        renewal_info.offerIdentifier             = None
        renewal_info.offerPeriod                 = None
        renewal_info.offerType                   = None
        renewal_info.originalTransactionId       = '2000001024993299'
        renewal_info.priceIncreaseStatus         = None
        renewal_info.productId                   = 'com.getsession.org.pro_sub'
        renewal_info.rawAutoRenewStatus          = None
        renewal_info.rawEnvironment              = 'Sandbox'
        renewal_info.rawExpirationIntent         = None
        renewal_info.rawOfferDiscountType        = None
        renewal_info.rawOfferType                = None
        renewal_info.rawPriceIncreaseStatus      = None
        renewal_info.recentSubscriptionStartDate = None
        renewal_info.renewalDate                 = None
        renewal_info.renewalPrice                = None
        renewal_info.signedDate                  = 1759302518835

        tx_info                                  = AppleJWSTransactionDecodedPayload()
        tx_info.appAccountToken                  = None
        tx_info.appTransactionId                 = '704897469903383919'
        tx_info.bundleId                         = 'com.loki-project.loki-messenger'
        tx_info.currency                         = 'AUD'
        tx_info.environment                      = AppleEnvironment.SANDBOX
        tx_info.expiresDate                      = 1759302732000
        tx_info.inAppOwnershipType               = AppleInAppOwnershipType.PURCHASED
        tx_info.isUpgraded                       = None
        tx_info.offerDiscountType                = None
        tx_info.offerIdentifier                  = None
        tx_info.offerPeriod                      = None
        tx_info.offerType                        = None
        tx_info.originalPurchaseDate             = 1759301833000
        tx_info.originalTransactionId            = '2000001024993299'
        tx_info.price                            = 1990
        tx_info.productId                        = 'com.getsession.org.pro_sub'
        tx_info.purchaseDate                     = 1759302552000
        tx_info.quantity                         = 1
        tx_info.rawEnvironment                   = 'Sandbox'
        tx_info.rawInAppOwnershipType            = 'PURCHASED'
        tx_info.rawOfferDiscountType             = None
        tx_info.rawOfferType                     = None
        tx_info.rawRevocationReason              = None
        tx_info.rawTransactionReason             = 'RENEWAL'
        tx_info.rawType                          = 'Auto-Renewable Subscription'
        tx_info.revocationDate                   = None
        tx_info.revocationReason                 = None
        tx_info.signedDate                       = 1759302518835
        tx_info.storefront                       = 'AUS'
        tx_info.storefrontId                     = '143460'
        tx_info.subscriptionGroupIdentifier      = '21752814'
        tx_info.transactionId                    = '2000001024998954'
        tx_info.transactionReason                = AppleTransactionReason.RENEWAL
        tx_info.type                             = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        tx_info.webOrderLineItemId               = '2000000113755461'

        notification = platform_apple.DecodedNotification(body=body, tx_info=tx_info, renewal_info=renewal_info)
        err = base.ErrorSink()
        platform_apple.handle_notification(decoded_notification=notification, sql_conn=test.sql_conn, err=err)
        assert not err.has(), err.msg_list

        # NOTE: Subscription renewal should be unredeemed
        unredeemed_list: list[backend.PaymentRow]             = backend.get_unredeemed_payments_list(test.sql_conn)
        assert len(unredeemed_list)                          == 1
        assert unredeemed_list[0].master_pkey                == None
        assert unredeemed_list[0].status                     == base.PaymentStatus.Unredeemed
        assert unredeemed_list[0].payment_provider           == base.PaymentProvider.iOSAppStore
        assert unredeemed_list[0].apple.original_tx_id       == tx_info.originalTransactionId
        assert unredeemed_list[0].apple.tx_id                == tx_info.transactionId
        assert unredeemed_list[0].apple.web_line_order_tx_id == tx_info.webOrderLineItemId

        # NOTE: Then claim the payment
        master_key   = nacl.signing.SigningKey.generate()
        rotating_key = nacl.signing.SigningKey.generate()

        version = 0
        add_pro_payment_tx             = backend.AddProPaymentUserTransaction()
        add_pro_payment_tx.provider    = base.PaymentProvider.iOSAppStore
        add_pro_payment_tx.apple_tx_id = unredeemed_list[0].apple.tx_id
        payment_hash_to_sign: bytes = backend.make_add_pro_payment_hash(version=version,
                                                                        master_pkey=master_key.verify_key,
                                                                        rotating_pkey=rotating_key.verify_key,
                                                                        payment_tx=add_pro_payment_tx)

        # NOTE: POST and get response
        response: werkzeug.test.TestResponse = test.flask_client.post(server.FLASK_ROUTE_ADD_PRO_PAYMENT, json={
            'version': version,
            'master_pkey':   bytes(master_key.verify_key).hex(),
            'rotating_pkey': bytes(rotating_key.verify_key).hex(),
            'master_sig':    bytes(master_key.sign(payment_hash_to_sign).signature).hex(),
            'rotating_sig':  bytes(rotating_key.sign(payment_hash_to_sign).signature).hex(),
            'payment_tx': {
                'provider':    add_pro_payment_tx.provider.value,
                'apple_tx_id': add_pro_payment_tx.apple_tx_id,
            }
        })

        # NOTE: Parse the JSON from the response
        response_json = json.loads(response.data)
        assert isinstance(response_json, dict), f'Response {response.body}'

        # NOTE: Parse status from response
        assert response_json['status'] == 0,  f'Response was: {json.dumps(response_json, indent=2)}'
        assert 'errors' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

        # NOTE: Parse result object is at root
        assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
        result_json = response_json['result']

        # NOTE: Extract the fields
        assert isinstance(result_json, dict)
        result_version:            int = base.json_dict_require_int(d=result_json, key='version',          err=err)
        result_gen_index_hash_hex: str = base.json_dict_require_str(d=result_json, key='gen_index_hash',   err=err)
        result_rotating_pkey_hex:  str = base.json_dict_require_str(d=result_json, key='rotating_pkey',    err=err)
        result_expiry_unix_ts_ms:  int = base.json_dict_require_int(d=result_json, key='expiry_unix_ts_ms', err=err)
        result_sig_hex:            str = base.json_dict_require_str(d=result_json, key='sig',              err=err)
        assert len(err.msg_list) == 0, '{err.msg_list}'

        # NOTE: Parse hex fields to bytes
        result_rotating_pkey  = nacl.signing.VerifyKey(base.hex_to_bytes(hex=result_rotating_pkey_hex,  label='Rotating public key',   hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2, err=err))
        result_sig            =                        base.hex_to_bytes(hex=result_sig_hex,            label='Signature',             hex_len=nacl.bindings.crypto_sign_BYTES * 2,          err=err)
        result_gen_index_hash =                        base.hex_to_bytes(hex=result_gen_index_hash_hex, label='Generation index hash', hex_len=backend.BLAKE2B_DIGEST_SIZE * 2, err=err)
        assert len(err.msg_list) == 0, '{err.msg_list}'

        # NOTE: Check the rotating key returned matches what we asked the server to sign
        assert result_rotating_pkey == rotating_key.verify_key

        # NOTE: Check that the server signed our proof w/ their public key
        proof_hash: bytes = backend.build_proof_hash(result_version, result_gen_index_hash, result_rotating_pkey, result_expiry_unix_ts_ms)
        _ = test.db.runtime.backend_key.verify_key.verify(smessage=proof_hash, signature=result_sig)

    # The following is a sequence of notifications/events that transpired for the same account under
    # the same billing cycle (e.g. a subscribe, cancelling of subscription, then expiring). Since
    # it's under the same billing cycle they all have the same original TX ID as well as the same
    # web line order TX ID.
    #
    # Having the same web line order TX ID and original transaction ID is essential for these tests
    # to work such that state changes (like disabling auto-renewal) updates the correct transaction
    # on our backend.
    #
    # This was done by executing these sequences in the time-frame that a subscription is active for
    # on Apple's sandbox environment.
    with TestingContext(db_path='file:test_platform_apple_db?mode=memory&cache=shared', uri=True) as test:
        if 1: # Subscribe notification
            # NOTE: Original payload (requires keys to decrypt)
            if 0:
                core:                      platform_apple.Core       = platform_apple.init()
                notification_payload_json: dict[str, base.JSONValue] = json.loads('''
                {
                  "signedPayload": "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJub3RpZmljYXRpb25UeXBlIjoiU1VCU0NSSUJFRCIsInN1YnR5cGUiOiJSRVNVQlNDUklCRSIsIm5vdGlmaWNhdGlvblVVSUQiOiI5Zjk3MzBmOC1mM2RmLTQzNmEtYjdlNS1lODVlZjljNmFmZTQiLCJkYXRhIjp7ImFwcEFwcGxlSWQiOjE0NzAxNjg4NjgsImJ1bmRsZUlkIjoiY29tLmxva2ktcHJvamVjdC5sb2tpLW1lc3NlbmdlciIsImJ1bmRsZVZlcnNpb24iOiI2MzciLCJlbnZpcm9ubWVudCI6IlNhbmRib3giLCJzaWduZWRUcmFuc2FjdGlvbkluZm8iOiJleUpoYkdjaU9pSkZVekkxTmlJc0luZzFZeUk2V3lKTlNVbEZUVlJEUTBFM1lXZEJkMGxDUVdkSlVWSTRTMGg2Wkc0MU5UUmFMMVZ2Y21Ga1RuZzVkSHBCUzBKblozRm9hMnBQVUZGUlJFRjZRakZOVlZGM1VXZFpSRlpSVVVSRVJIUkNZMGhDYzFwVFFsaGlNMHB6V2toa2NGcEhWV2RTUjFZeVdsZDRkbU5IVm5sSlJrcHNZa2RHTUdGWE9YVmplVUpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJVeE5RV3RIUVRGVlJVTjNkME5TZWxsNFJYcEJVa0puVGxaQ1FXOU5RMnRHZDJOSGVHeEpSV3gxV1hrMGVFTjZRVXBDWjA1V1FrRlpWRUZzVmxSTlFqUllSRlJKTVUxRWEzaFBWRVUxVGtSUk1VMVdiMWhFVkVrelRWUkJlRTE2UlROT1JHTjVUVEZ2ZDJkYVNYaFJSRUVyUW1kT1ZrSkJUVTFPTVVKNVlqSlJaMUpWVGtSSlJURm9XWGxDUW1OSVFXZFZNMUoyWTIxVloxbFhOV3RKUjJ4VlpGYzFiR041UWxSa1J6bDVXbE5DVTFwWFRteGhXRUl3U1VaT2NGb3lOWEJpYldONFRFUkJjVUpuVGxaQ1FYTk5TVEJHZDJOSGVHeEpSbVIyWTIxNGEyUXliR3RhVTBKRldsaGFiR0pIT1hkYVdFbG5WVzFXYzFsWVVuQmlNalY2VFZKTmQwVlJXVVJXVVZGTFJFRndRbU5JUW5OYVUwSktZbTFOZFUxUmMzZERVVmxFVmxGUlIwVjNTbFpWZWtKYVRVSk5SMEo1Y1VkVFRUUTVRV2RGUjBORGNVZFRUVFE1UVhkRlNFRXdTVUZDVG01V2RtaGpkamRwVkNzM1JYZzFkRUpOUW1keVVYTndTSHBKYzFoU2FUQlplR1psYXpkc2RqaDNSVzFxTDJKSWFWZDBUbmRLY1dNeVFtOUllbk5SYVVWcVVEZExSa2xKUzJjMFdUaDVNQzl1ZVc1MVFXMXFaMmRKU1UxSlNVTkNSRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDT0VkQk1WVmtTWGRSV1UxQ1lVRkdSRGgyYkVOT1VqQXhSRXB0YVdjNU4ySkNPRFZqSzJ4clIwdGFUVWhCUjBORGMwZEJVVlZHUW5kRlFrSkhVWGRaYWtGMFFtZG5ja0puUlVaQ1VXTjNRVzlaYUdGSVVqQmpSRzkyVERKT2JHTnVVbnBNYlVaM1kwZDRiRXh0VG5aaVV6a3paREpTZVZwNldYVmFSMVo1VFVSRlIwTkRjMGRCVVZWR1FucEJRbWhwVm05a1NGSjNUMms0ZG1JeVRucGpRelZvWTBoQ2MxcFROV3BpTWpCMllqSk9lbU5FUVhwTVdHUXpXa2hLYms1cVFYbE5TVWxDU0dkWlJGWlNNR2RDU1VsQ1JsUkRRMEZTUlhkblowVk9RbWR2Y1docmFVYzVNazVyUWxGWlFrMUpTQ3ROU1VoRVFtZG5ja0puUlVaQ1VXTkRRV3BEUW5SbmVVSnpNVXBzWWtkc2FHSnRUbXhKUnpsMVNVaFNiMkZZVFdkWk1sWjVaRWRzYldGWFRtaGtSMVZuV1c1cloxbFhOVFZKU0VKb1kyNVNOVWxIUm5wak0xWjBXbGhOWjFsWFRtcGFXRUl3V1ZjMWFscFRRblphYVVJd1lVZFZaMlJIYUd4aWFVSm9ZMGhDYzJGWFRtaFpiWGhzU1VoT01GbFhOV3RaV0VwclNVaFNiR050TVhwSlIwWjFXa05DYW1JeU5XdGhXRkp3WWpJMWVrbEhPVzFKU0ZaNldsTjNaMWt5Vm5sa1IyeHRZVmRPYUdSSFZXZGpSemx6WVZkT05VbEhSblZhUTBKcVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsSVFubFpWMDR3WVZkT2JFbElUakJaV0ZKc1lsZFdkV1JJVFhWTlJGbEhRME56UjBGUlZVWkNkMGxDUm1sd2IyUklVbmRQYVRoMlpETmtNMHh0Um5kalIzaHNURzFPZG1KVE9XcGFXRW93WVZkYWNGa3lSakJhVjBZeFpFZG9kbU50YkRCbFV6aDNTRkZaUkZaU01FOUNRbGxGUmtsR2FXOUhOSGROVFZaQk1XdDFPWHBLYlVkT1VFRldiak5sY1UxQk5FZEJNVlZrUkhkRlFpOTNVVVZCZDBsSVowUkJVVUpuYjNGb2EybEhPVEpPYTBKbmMwSkNRVWxHUVVSQlMwSm5aM0ZvYTJwUFVGRlJSRUYzVG5CQlJFSnRRV3BGUVN0eFdHNVNSVU0zYUZoSlYxWk1jMHg0ZW01cVVuQkplbEJtTjFaSWVqbFdMME5VYlRnclRFcHNjbEZsY0c1dFkxQjJSMHhPWTFnMldGQnViR05uVEVGQmFrVkJOVWxxVGxwTFoyYzFjRkUzT1d0dVJqUkpZbFJZWkV0Mk9IWjFkRWxFVFZoRWJXcFFWbFF6WkVkMlJuUnpSMUozV0U5NWQxSXlhMXBEWkZOeVptVnZkQ0lzSWsxSlNVUkdha05EUVhCNVowRjNTVUpCWjBsVlNYTkhhRkozY0RCak1tNTJWVFJaVTNsallXWlFWR3A2WWs1amQwTm5XVWxMYjFwSmVtb3dSVUYzVFhkYWVrVmlUVUpyUjBFeFZVVkJkM2RUVVZoQ2QySkhWV2RWYlRsMlpFTkNSRkZUUVhSSlJXTjZUVk5aZDBwQldVUldVVkZNUkVJeFFtTklRbk5hVTBKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVlJOUWtWSFFURlZSVU5uZDB0UldFSjNZa2RWWjFOWE5XcE1ha1ZNVFVGclIwRXhWVVZDYUUxRFZsWk5kMGhvWTA1TmFrVjNUWHBGTTAxcVFYcE9la1YzVjJoalRrMTZXWGROZWtVMVRVUkJkMDFFUVhkWGFrSXhUVlZSZDFGbldVUldVVkZFUkVSMFFtTklRbk5hVTBKWVlqTktjMXBJWkhCYVIxVm5Va2RXTWxwWGVIWmpSMVo1U1VaS2JHSkhSakJoVnpsMVkzbENSRnBZU2pCaFYxcHdXVEpHTUdGWE9YVkpSVVl4WkVkb2RtTnRiREJsVkVWTVRVRnJSMEV4VlVWRGQzZERVbnBaZUVWNlFWSkNaMDVXUWtGdlRVTnJSbmRqUjNoc1NVVnNkVmw1TkhoRGVrRktRbWRPVmtKQldWUkJiRlpVVFVoWmQwVkJXVWhMYjFwSmVtb3dRMEZSV1VaTE5FVkZRVU5KUkZsblFVVmljMUZMUXprMFVISnNWMjFhV0c1WVozUjRlbVJXU2t3NFZEQlRSMWx1WjBSU1IzQnVaMjR6VGpaUVZEaEtUVVZpTjBaRWFUUmlRbTFRYUVOdVdqTXZjM0UyVUVZdlkwZGpTMWhYYzB3MWRrOTBaVkpvZVVvME5YZ3pRVk5RTjJOUFFpdGhZVzg1TUdaamNIaFRkaTlGV2taaWJtbEJZazVuV2tkb1NXaHdTVzgwU0RaTlNVZ3pUVUpKUjBFeFZXUkZkMFZDTDNkUlNVMUJXVUpCWmpoRFFWRkJkMGgzV1VSV1VqQnFRa0puZDBadlFWVjFOMFJsYjFabmVtbEtjV3RwY0c1bGRuSXpjbkk1Y2t4S1MzTjNVbWRaU1V0M1dVSkNVVlZJUVZGRlJVOXFRVFJOUkZsSFEwTnpSMEZSVlVaQ2VrRkNhR2x3YjJSSVVuZFBhVGgyWWpKT2VtTkROV2hqU0VKeldsTTFhbUl5TUhaaU1rNTZZMFJCZWt4WFJuZGpSM2hzWTIwNWRtUkhUbWhhZWsxM1RuZFpSRlpTTUdaQ1JFRjNUR3BCYzI5RGNXZExTVmx0WVVoU01HTkViM1pNTWs1NVlrTTFhR05JUW5OYVV6VnFZakl3ZGxsWVFuZGlSMVo1WWpJNU1Ga3lSbTVOZVRWcVkyMTNkMGhSV1VSV1VqQlBRa0paUlVaRU9IWnNRMDVTTURGRVNtMXBaemszWWtJNE5XTXJiR3RIUzFwTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlFrSnFRVkZDWjI5eGFHdHBSemt5VG10Q1owbENRa0ZKUmtGRVFVdENaMmR4YUd0cVQxQlJVVVJCZDA1dlFVUkNiRUZxUWtGWWFGTnhOVWw1UzI5blRVTlFkSGMwT1RCQ1lVSTJOemREWVVWSFNsaDFabEZDTDBWeFdrZGtOa05UYW1sRGRFOXVkVTFVWWxoV1dHMTRlR040Wm10RFRWRkVWRk5RZUdGeVdsaDJUbkpyZUZVelZHdFZUVWt6TTNsNmRrWldWbEpVTkhkNFYwcERPVGswVDNOa1kxbzBLMUpIVG5OWlJIbFNOV2R0WkhJd2JrUkhaejBpTENKTlNVbERVWHBEUTBGamJXZEJkMGxDUVdkSlNVeGpXRGhwVGt4R1V6VlZkME5uV1VsTGIxcEplbW93UlVGM1RYZGFla1ZpVFVKclIwRXhWVVZCZDNkVFVWaENkMkpIVldkVmJUbDJaRU5DUkZGVFFYUkpSV042VFZOWmQwcEJXVVJXVVZGTVJFSXhRbU5JUW5OYVUwSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlZSTlFrVkhRVEZWUlVObmQwdFJXRUozWWtkVloxTlhOV3BNYWtWTVRVRnJSMEV4VlVWQ2FFMURWbFpOZDBob1kwNU5WRkYzVGtSTmQwMVVaM2hQVkVFeVYyaGpUazE2YTNkT1JFMTNUVlJuZUU5VVFUSlhha0p1VFZKemQwZFJXVVJXVVZGRVJFSktRbU5JUW5OYVUwSlRZakk1TUVsRlRrSkpRekJuVW5wTmVFcHFRV3RDWjA1V1FrRnpUVWhWUm5kalIzaHNTVVZPYkdOdVVuQmFiV3hxV1ZoU2NHSXlOR2RSV0ZZd1lVYzVlV0ZZVWpWTlVrMTNSVkZaUkZaUlVVdEVRWEJDWTBoQ2MxcFRRa3BpYlUxMVRWRnpkME5SV1VSV1VWRkhSWGRLVmxWNlFqSk5Ra0ZIUW5seFIxTk5ORGxCWjBWSFFsTjFRa0pCUVdsQk1rbEJRa3BxY0V4Nk1VRmpjVlIwYTNsS2VXZFNUV016VWtOV09HTlhhbFJ1U0dOR1FtSmFSSFZYYlVKVGNETmFTSFJtVkdwcVZIVjRlRVYwV0M4eFNEZFplVmxzTTBvMldWSmlWSHBDVUVWV2IwRXZWbWhaUkV0WU1VUjVlRTVDTUdOVVpHUnhXR3cxWkhaTlZucDBTelV4TjBsRWRsbDFWbFJhV0hCdGEwOXNSVXROWVU1RFRVVkJkMGhSV1VSV1VqQlBRa0paUlVaTWRYY3pjVVpaVFRScFlYQkpjVm96Y2pZNU5qWXZZWGw1VTNKTlFUaEhRVEZWWkVWM1JVSXZkMUZHVFVGTlFrRm1PSGRFWjFsRVZsSXdVRUZSU0M5Q1FWRkVRV2RGUjAxQmIwZERRM0ZIVTAwME9VSkJUVVJCTW1kQlRVZFZRMDFSUTBRMlkwaEZSbXcwWVZoVVVWa3laVE4yT1VkM1QwRkZXa3gxVGl0NVVtaElSa1F2TTIxbGIzbG9jRzEyVDNkblVGVnVVRmRVZUc1VE5HRjBLM0ZKZUZWRFRVY3hiV2xvUkVzeFFUTlZWRGd5VGxGNk5qQnBiVTlzVFRJM2FtSmtiMWgwTWxGbWVVWk5iU3RaYUdsa1JHdE1SakYyVEZWaFowMDJRbWRFTlRaTGVVdEJQVDBpWFgwLmV5SjBjbUZ1YzJGamRHbHZia2xrSWpvaU1qQXdNREF3TVRBeU5UWTROak14TXlJc0ltOXlhV2RwYm1Gc1ZISmhibk5oWTNScGIyNUpaQ0k2SWpJd01EQXdNREV3TWpRNU9UTXlPVGtpTENKM1pXSlBjbVJsY2t4cGJtVkpkR1Z0U1dRaU9pSXlNREF3TURBd01URXpPRFEwTnpBMklpd2lZblZ1Wkd4bFNXUWlPaUpqYjIwdWJHOXJhUzF3Y205cVpXTjBMbXh2YTJrdGJXVnpjMlZ1WjJWeUlpd2ljSEp2WkhWamRFbGtJam9pWTI5dExtZGxkSE5sYzNOcGIyNHViM0puTG5CeWIxOXpkV0lpTENKemRXSnpZM0pwY0hScGIyNUhjbTkxY0Vsa1pXNTBhV1pwWlhJaU9pSXlNVGMxTWpneE5DSXNJbkIxY21Ob1lYTmxSR0YwWlNJNk1UYzFPVE00T0RjMk56QXdNQ3dpYjNKcFoybHVZV3hRZFhKamFHRnpaVVJoZEdVaU9qRTNOVGt6TURFNE16TXdNREFzSW1WNGNHbHlaWE5FWVhSbElqb3hOelU1TXpnNE9UUTNNREF3TENKeGRXRnVkR2wwZVNJNk1Td2lkSGx3WlNJNklrRjFkRzh0VW1WdVpYZGhZbXhsSUZOMVluTmpjbWx3ZEdsdmJpSXNJbWx1UVhCd1QzZHVaWEp6YUdsd1ZIbHdaU0k2SWxCVlVrTklRVk5GUkNJc0luTnBaMjVsWkVSaGRHVWlPakUzTlRrek9EZzNOelk1TkRFc0ltVnVkbWx5YjI1dFpXNTBJam9pVTJGdVpHSnZlQ0lzSW5SeVlXNXpZV04wYVc5dVVtVmhjMjl1SWpvaVVGVlNRMGhCVTBVaUxDSnpkRzl5WldaeWIyNTBJam9pUVZWVElpd2ljM1J2Y21WbWNtOXVkRWxrSWpvaU1UUXpORFl3SWl3aWNISnBZMlVpT2pFNU9UQXNJbU4xY25KbGJtTjVJam9pUVZWRUlpd2lZWEJ3VkhKaGJuTmhZM1JwYjI1SlpDSTZJamN3TkRnNU56UTJPVGt3TXpNNE16a3hPU0o5LnhLUER1bEhkMUlxOHdRbWt4OTlyYzVaWnNOdGliNUhPaHRWbnM2MmJsUlFLX1laYlJLai04WXpLNlF6RS1VbVZLM1h1NzNDQzBUQ1UxVmxqWXNqYXV3Iiwic2lnbmVkUmVuZXdhbEluZm8iOiJleUpoYkdjaU9pSkZVekkxTmlJc0luZzFZeUk2V3lKTlNVbEZUVlJEUTBFM1lXZEJkMGxDUVdkSlVWSTRTMGg2Wkc0MU5UUmFMMVZ2Y21Ga1RuZzVkSHBCUzBKblozRm9hMnBQVUZGUlJFRjZRakZOVlZGM1VXZFpSRlpSVVVSRVJIUkNZMGhDYzFwVFFsaGlNMHB6V2toa2NGcEhWV2RTUjFZeVdsZDRkbU5IVm5sSlJrcHNZa2RHTUdGWE9YVmplVUpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJVeE5RV3RIUVRGVlJVTjNkME5TZWxsNFJYcEJVa0puVGxaQ1FXOU5RMnRHZDJOSGVHeEpSV3gxV1hrMGVFTjZRVXBDWjA1V1FrRlpWRUZzVmxSTlFqUllSRlJKTVUxRWEzaFBWRVUxVGtSUk1VMVdiMWhFVkVrelRWUkJlRTE2UlROT1JHTjVUVEZ2ZDJkYVNYaFJSRUVyUW1kT1ZrSkJUVTFPTVVKNVlqSlJaMUpWVGtSSlJURm9XWGxDUW1OSVFXZFZNMUoyWTIxVloxbFhOV3RKUjJ4VlpGYzFiR041UWxSa1J6bDVXbE5DVTFwWFRteGhXRUl3U1VaT2NGb3lOWEJpYldONFRFUkJjVUpuVGxaQ1FYTk5TVEJHZDJOSGVHeEpSbVIyWTIxNGEyUXliR3RhVTBKRldsaGFiR0pIT1hkYVdFbG5WVzFXYzFsWVVuQmlNalY2VFZKTmQwVlJXVVJXVVZGTFJFRndRbU5JUW5OYVUwSktZbTFOZFUxUmMzZERVVmxFVmxGUlIwVjNTbFpWZWtKYVRVSk5SMEo1Y1VkVFRUUTVRV2RGUjBORGNVZFRUVFE1UVhkRlNFRXdTVUZDVG01V2RtaGpkamRwVkNzM1JYZzFkRUpOUW1keVVYTndTSHBKYzFoU2FUQlplR1psYXpkc2RqaDNSVzFxTDJKSWFWZDBUbmRLY1dNeVFtOUllbk5SYVVWcVVEZExSa2xKUzJjMFdUaDVNQzl1ZVc1MVFXMXFaMmRKU1UxSlNVTkNSRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDT0VkQk1WVmtTWGRSV1UxQ1lVRkdSRGgyYkVOT1VqQXhSRXB0YVdjNU4ySkNPRFZqSzJ4clIwdGFUVWhCUjBORGMwZEJVVlZHUW5kRlFrSkhVWGRaYWtGMFFtZG5ja0puUlVaQ1VXTjNRVzlaYUdGSVVqQmpSRzkyVERKT2JHTnVVbnBNYlVaM1kwZDRiRXh0VG5aaVV6a3paREpTZVZwNldYVmFSMVo1VFVSRlIwTkRjMGRCVVZWR1FucEJRbWhwVm05a1NGSjNUMms0ZG1JeVRucGpRelZvWTBoQ2MxcFROV3BpTWpCMllqSk9lbU5FUVhwTVdHUXpXa2hLYms1cVFYbE5TVWxDU0dkWlJGWlNNR2RDU1VsQ1JsUkRRMEZTUlhkblowVk9RbWR2Y1docmFVYzVNazVyUWxGWlFrMUpTQ3ROU1VoRVFtZG5ja0puUlVaQ1VXTkRRV3BEUW5SbmVVSnpNVXBzWWtkc2FHSnRUbXhKUnpsMVNVaFNiMkZZVFdkWk1sWjVaRWRzYldGWFRtaGtSMVZuV1c1cloxbFhOVFZKU0VKb1kyNVNOVWxIUm5wak0xWjBXbGhOWjFsWFRtcGFXRUl3V1ZjMWFscFRRblphYVVJd1lVZFZaMlJIYUd4aWFVSm9ZMGhDYzJGWFRtaFpiWGhzU1VoT01GbFhOV3RaV0VwclNVaFNiR050TVhwSlIwWjFXa05DYW1JeU5XdGhXRkp3WWpJMWVrbEhPVzFKU0ZaNldsTjNaMWt5Vm5sa1IyeHRZVmRPYUdSSFZXZGpSemx6WVZkT05VbEhSblZhUTBKcVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsSVFubFpWMDR3WVZkT2JFbElUakJaV0ZKc1lsZFdkV1JJVFhWTlJGbEhRME56UjBGUlZVWkNkMGxDUm1sd2IyUklVbmRQYVRoMlpETmtNMHh0Um5kalIzaHNURzFPZG1KVE9XcGFXRW93WVZkYWNGa3lSakJhVjBZeFpFZG9kbU50YkRCbFV6aDNTRkZaUkZaU01FOUNRbGxGUmtsR2FXOUhOSGROVFZaQk1XdDFPWHBLYlVkT1VFRldiak5sY1UxQk5FZEJNVlZrUkhkRlFpOTNVVVZCZDBsSVowUkJVVUpuYjNGb2EybEhPVEpPYTBKbmMwSkNRVWxHUVVSQlMwSm5aM0ZvYTJwUFVGRlJSRUYzVG5CQlJFSnRRV3BGUVN0eFdHNVNSVU0zYUZoSlYxWk1jMHg0ZW01cVVuQkplbEJtTjFaSWVqbFdMME5VYlRnclRFcHNjbEZsY0c1dFkxQjJSMHhPWTFnMldGQnViR05uVEVGQmFrVkJOVWxxVGxwTFoyYzFjRkUzT1d0dVJqUkpZbFJZWkV0Mk9IWjFkRWxFVFZoRWJXcFFWbFF6WkVkMlJuUnpSMUozV0U5NWQxSXlhMXBEWkZOeVptVnZkQ0lzSWsxSlNVUkdha05EUVhCNVowRjNTVUpCWjBsVlNYTkhhRkozY0RCak1tNTJWVFJaVTNsallXWlFWR3A2WWs1amQwTm5XVWxMYjFwSmVtb3dSVUYzVFhkYWVrVmlUVUpyUjBFeFZVVkJkM2RUVVZoQ2QySkhWV2RWYlRsMlpFTkNSRkZUUVhSSlJXTjZUVk5aZDBwQldVUldVVkZNUkVJeFFtTklRbk5hVTBKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVlJOUWtWSFFURlZSVU5uZDB0UldFSjNZa2RWWjFOWE5XcE1ha1ZNVFVGclIwRXhWVVZDYUUxRFZsWk5kMGhvWTA1TmFrVjNUWHBGTTAxcVFYcE9la1YzVjJoalRrMTZXWGROZWtVMVRVUkJkMDFFUVhkWGFrSXhUVlZSZDFGbldVUldVVkZFUkVSMFFtTklRbk5hVTBKWVlqTktjMXBJWkhCYVIxVm5Va2RXTWxwWGVIWmpSMVo1U1VaS2JHSkhSakJoVnpsMVkzbENSRnBZU2pCaFYxcHdXVEpHTUdGWE9YVkpSVVl4WkVkb2RtTnRiREJsVkVWTVRVRnJSMEV4VlVWRGQzZERVbnBaZUVWNlFWSkNaMDVXUWtGdlRVTnJSbmRqUjNoc1NVVnNkVmw1TkhoRGVrRktRbWRPVmtKQldWUkJiRlpVVFVoWmQwVkJXVWhMYjFwSmVtb3dRMEZSV1VaTE5FVkZRVU5KUkZsblFVVmljMUZMUXprMFVISnNWMjFhV0c1WVozUjRlbVJXU2t3NFZEQlRSMWx1WjBSU1IzQnVaMjR6VGpaUVZEaEtUVVZpTjBaRWFUUmlRbTFRYUVOdVdqTXZjM0UyVUVZdlkwZGpTMWhYYzB3MWRrOTBaVkpvZVVvME5YZ3pRVk5RTjJOUFFpdGhZVzg1TUdaamNIaFRkaTlGV2taaWJtbEJZazVuV2tkb1NXaHdTVzgwU0RaTlNVZ3pUVUpKUjBFeFZXUkZkMFZDTDNkUlNVMUJXVUpCWmpoRFFWRkJkMGgzV1VSV1VqQnFRa0puZDBadlFWVjFOMFJsYjFabmVtbEtjV3RwY0c1bGRuSXpjbkk1Y2t4S1MzTjNVbWRaU1V0M1dVSkNVVlZJUVZGRlJVOXFRVFJOUkZsSFEwTnpSMEZSVlVaQ2VrRkNhR2x3YjJSSVVuZFBhVGgyWWpKT2VtTkROV2hqU0VKeldsTTFhbUl5TUhaaU1rNTZZMFJCZWt4WFJuZGpSM2hzWTIwNWRtUkhUbWhhZWsxM1RuZFpSRlpTTUdaQ1JFRjNUR3BCYzI5RGNXZExTVmx0WVVoU01HTkViM1pNTWs1NVlrTTFhR05JUW5OYVV6VnFZakl3ZGxsWVFuZGlSMVo1WWpJNU1Ga3lSbTVOZVRWcVkyMTNkMGhSV1VSV1VqQlBRa0paUlVaRU9IWnNRMDVTTURGRVNtMXBaemszWWtJNE5XTXJiR3RIUzFwTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlFrSnFRVkZDWjI5eGFHdHBSemt5VG10Q1owbENRa0ZKUmtGRVFVdENaMmR4YUd0cVQxQlJVVVJCZDA1dlFVUkNiRUZxUWtGWWFGTnhOVWw1UzI5blRVTlFkSGMwT1RCQ1lVSTJOemREWVVWSFNsaDFabEZDTDBWeFdrZGtOa05UYW1sRGRFOXVkVTFVWWxoV1dHMTRlR040Wm10RFRWRkVWRk5RZUdGeVdsaDJUbkpyZUZVelZHdFZUVWt6TTNsNmRrWldWbEpVTkhkNFYwcERPVGswVDNOa1kxbzBLMUpIVG5OWlJIbFNOV2R0WkhJd2JrUkhaejBpTENKTlNVbERVWHBEUTBGamJXZEJkMGxDUVdkSlNVeGpXRGhwVGt4R1V6VlZkME5uV1VsTGIxcEplbW93UlVGM1RYZGFla1ZpVFVKclIwRXhWVVZCZDNkVFVWaENkMkpIVldkVmJUbDJaRU5DUkZGVFFYUkpSV042VFZOWmQwcEJXVVJXVVZGTVJFSXhRbU5JUW5OYVUwSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlZSTlFrVkhRVEZWUlVObmQwdFJXRUozWWtkVloxTlhOV3BNYWtWTVRVRnJSMEV4VlVWQ2FFMURWbFpOZDBob1kwNU5WRkYzVGtSTmQwMVVaM2hQVkVFeVYyaGpUazE2YTNkT1JFMTNUVlJuZUU5VVFUSlhha0p1VFZKemQwZFJXVVJXVVZGRVJFSktRbU5JUW5OYVUwSlRZakk1TUVsRlRrSkpRekJuVW5wTmVFcHFRV3RDWjA1V1FrRnpUVWhWUm5kalIzaHNTVVZPYkdOdVVuQmFiV3hxV1ZoU2NHSXlOR2RSV0ZZd1lVYzVlV0ZZVWpWTlVrMTNSVkZaUkZaUlVVdEVRWEJDWTBoQ2MxcFRRa3BpYlUxMVRWRnpkME5SV1VSV1VWRkhSWGRLVmxWNlFqSk5Ra0ZIUW5seFIxTk5ORGxCWjBWSFFsTjFRa0pCUVdsQk1rbEJRa3BxY0V4Nk1VRmpjVlIwYTNsS2VXZFNUV016VWtOV09HTlhhbFJ1U0dOR1FtSmFSSFZYYlVKVGNETmFTSFJtVkdwcVZIVjRlRVYwV0M4eFNEZFplVmxzTTBvMldWSmlWSHBDVUVWV2IwRXZWbWhaUkV0WU1VUjVlRTVDTUdOVVpHUnhXR3cxWkhaTlZucDBTelV4TjBsRWRsbDFWbFJhV0hCdGEwOXNSVXROWVU1RFRVVkJkMGhSV1VSV1VqQlBRa0paUlVaTWRYY3pjVVpaVFRScFlYQkpjVm96Y2pZNU5qWXZZWGw1VTNKTlFUaEhRVEZWWkVWM1JVSXZkMUZHVFVGTlFrRm1PSGRFWjFsRVZsSXdVRUZSU0M5Q1FWRkVRV2RGUjAxQmIwZERRM0ZIVTAwME9VSkJUVVJCTW1kQlRVZFZRMDFSUTBRMlkwaEZSbXcwWVZoVVVWa3laVE4yT1VkM1QwRkZXa3gxVGl0NVVtaElSa1F2TTIxbGIzbG9jRzEyVDNkblVGVnVVRmRVZUc1VE5HRjBLM0ZKZUZWRFRVY3hiV2xvUkVzeFFUTlZWRGd5VGxGNk5qQnBiVTlzVFRJM2FtSmtiMWgwTWxGbWVVWk5iU3RaYUdsa1JHdE1SakYyVEZWaFowMDJRbWRFTlRaTGVVdEJQVDBpWFgwLmV5SnZjbWxuYVc1aGJGUnlZVzV6WVdOMGFXOXVTV1FpT2lJeU1EQXdNREF4TURJME9Ua3pNams1SWl3aVlYVjBiMUpsYm1WM1VISnZaSFZqZEVsa0lqb2lZMjl0TG1kbGRITmxjM05wYjI0dWIzSm5MbkJ5YjE5emRXSWlMQ0p3Y205a2RXTjBTV1FpT2lKamIyMHVaMlYwYzJWemMybHZiaTV2Y21jdWNISnZYM04xWWlJc0ltRjFkRzlTWlc1bGQxTjBZWFIxY3lJNk1Td2ljbVZ1WlhkaGJGQnlhV05sSWpveE9Ua3dMQ0pqZFhKeVpXNWplU0k2SWtGVlJDSXNJbk5wWjI1bFpFUmhkR1VpT2pFM05Ua3pPRGczTnpZNU5ERXNJbVZ1ZG1seWIyNXRaVzUwSWpvaVUyRnVaR0p2ZUNJc0luSmxZMlZ1ZEZOMVluTmpjbWx3ZEdsdmJsTjBZWEowUkdGMFpTSTZNVGMxT1RNNE9EYzJOekF3TUN3aWNtVnVaWGRoYkVSaGRHVWlPakUzTlRrek9EZzVORGN3TURBc0ltRndjRlJ5WVc1ellXTjBhVzl1U1dRaU9pSTNNRFE0T1RjME5qazVNRE16T0RNNU1Ua2lmUS5EQlJyR05FMllxTDBhbWpQVnc2MmdacWZZdFRxb1NaR1dobDBzS0VwVmZ5bjQxYWFWUktIQTdDem50TFY3OFJEeUUzMHB6QXNITTNTaEgtZUtYRHN1QSIsInN0YXR1cyI6MX0sInZlcnNpb24iOiIyLjAiLCJzaWduZWREYXRlIjoxNzU5Mzg4Nzc2OTQxfQ.rFZHq2jdG7GTrVVrE3rOchYhuWN9Ehxmofy8wKKD_NfgmiRIbgvqrksZkV7R9IIlOT9pf0d87SGJY28Qr5RmAg"
                }
                ''')

                signed_payload: str = typing.cast(str, notification_payload_json['signedPayload'])
                body: AppleResponseBodyV2DecodedPayload = core.signed_data_verifier.verify_and_decode_notification(signed_payload)
                dump_apple_signed_payloads(core, body)

            # NOTE: Generated by dump_apple_signed_payloads
            # NOTE: Signed Payload
            body                                     = AppleResponseBodyV2DecodedPayload()
            body_data                                = AppleData()
            body_data.appAppleId                     = 1470168868
            body_data.bundleId                       = 'com.loki-project.loki-messenger'
            body_data.bundleVersion                  = '637'
            body_data.consumptionRequestReason       = None
            body_data.environment                    = AppleEnvironment.SANDBOX
            body_data.rawConsumptionRequestReason    = None
            body_data.rawEnvironment                 = 'Sandbox'
            body_data.rawStatus                      = 1
            body_data.signedRenewalInfo              = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MSwicmVuZXdhbFByaWNlIjoxOTkwLCJjdXJyZW5jeSI6IkFVRCIsInNpZ25lZERhdGUiOjE3NTkzODg3NzY5NDEsImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc1OTM4ODc2NzAwMCwicmVuZXdhbERhdGUiOjE3NTkzODg5NDcwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.DBRrGNE2YqL0amjPVw62gZqfYtTqoSZGWhl0sKEpVfyn41aaVRKHA7CzntLV78RDyE30pzAsHM3ShH-eKXDsuA'
            body_data.signedTransactionInfo          = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNTY4NjMxMyIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTEzODQ0NzA2IiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTM4ODc2NzAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5Mzg4OTQ3MDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTkzODg3NzY5NDEsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.xKPDulHd1Iq8wQmkx99rc5ZZsNtib5HOhtVns62blRQK_YZbRKj-8YzK6QzE-UmVK3Xu73CC0TCU1VljYsjauw'
            body_data.status                         = AppleStatus.ACTIVE
            body.data                                = body_data
            body.externalPurchaseToken               = None
            body.notificationType                    = AppleNotificationTypeV2.SUBSCRIBED
            body.notificationUUID                    = '9f9730f8-f3df-436a-b7e5-e85ef9c6afe4'
            body.rawNotificationType                 = 'SUBSCRIBED'
            body.rawSubtype                          = 'RESUBSCRIBE'
            body.signedDate                          = 1759388776941
            body.subtype                             = AppleSubtype.RESUBSCRIBE
            body.summary                             = None
            body.version                             = '2.0'

            # NOTE: Signed Renewal Info
            renewal_info                             = AppleJWSRenewalInfoDecodedPayload()
            renewal_info.appAccountToken             = None
            renewal_info.appTransactionId            = '704897469903383919'
            renewal_info.autoRenewProductId          = None
            renewal_info.autoRenewStatus             = None
            renewal_info.currency                    = 'AUD'
            renewal_info.eligibleWinBackOfferIds     = None
            renewal_info.environment                 = AppleEnvironment.SANDBOX
            renewal_info.expirationIntent            = None
            renewal_info.gracePeriodExpiresDate      = None
            renewal_info.isInBillingRetryPeriod      = None
            renewal_info.offerDiscountType           = None
            renewal_info.offerIdentifier             = None
            renewal_info.offerPeriod                 = None
            renewal_info.offerType                   = None
            renewal_info.originalTransactionId       = '2000001024993299'
            renewal_info.priceIncreaseStatus         = None
            renewal_info.productId                   = 'com.getsession.org.pro_sub'
            renewal_info.rawAutoRenewStatus          = None
            renewal_info.rawEnvironment              = 'Sandbox'
            renewal_info.rawExpirationIntent         = None
            renewal_info.rawOfferDiscountType        = None
            renewal_info.rawOfferType                = None
            renewal_info.rawPriceIncreaseStatus      = None
            renewal_info.recentSubscriptionStartDate = None
            renewal_info.renewalDate                 = None
            renewal_info.renewalPrice                = None
            renewal_info.signedDate                  = 1759388776941

            # NOTE: Signed Transaction Info
            tx_info                                  = AppleJWSTransactionDecodedPayload()
            tx_info.appAccountToken                  = None
            tx_info.appTransactionId                 = '704897469903383919'
            tx_info.bundleId                         = 'com.loki-project.loki-messenger'
            tx_info.currency                         = 'AUD'
            tx_info.environment                      = AppleEnvironment.SANDBOX
            tx_info.expiresDate                      = 1759388947000
            tx_info.inAppOwnershipType               = AppleInAppOwnershipType.PURCHASED
            tx_info.isUpgraded                       = None
            tx_info.offerDiscountType                = None
            tx_info.offerIdentifier                  = None
            tx_info.offerPeriod                      = None
            tx_info.offerType                        = None
            tx_info.originalPurchaseDate             = 1759301833000
            tx_info.originalTransactionId            = '2000001024993299'
            tx_info.price                            = 1990
            tx_info.productId                        = 'com.getsession.org.pro_sub'
            tx_info.purchaseDate                     = 1759388767000
            tx_info.quantity                         = 1
            tx_info.rawEnvironment                   = 'Sandbox'
            tx_info.rawInAppOwnershipType            = 'PURCHASED'
            tx_info.rawOfferDiscountType             = None
            tx_info.rawOfferType                     = None
            tx_info.rawRevocationReason              = None
            tx_info.rawTransactionReason             = 'PURCHASE'
            tx_info.rawType                          = 'Auto-Renewable Subscription'
            tx_info.revocationDate                   = None
            tx_info.revocationReason                 = None
            tx_info.signedDate                       = 1759388776941
            tx_info.storefront                       = 'AUS'
            tx_info.storefrontId                     = '143460'
            tx_info.subscriptionGroupIdentifier      = '21752814'
            tx_info.transactionId                    = '2000001025686313'
            tx_info.transactionReason                = AppleTransactionReason.PURCHASE
            tx_info.type                             = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
            tx_info.webOrderLineItemId               = '2000000113844706'

            decoded_notification = platform_apple.DecodedNotification(body=body, tx_info=tx_info, renewal_info=renewal_info)

            err = base.ErrorSink()
            platform_apple.handle_notification(decoded_notification=decoded_notification, sql_conn=test.sql_conn, err=err)
            assert not err.has(), err.msg_list

            # NOTE: Subscription purchase is unredeemed
            unredeemed_list: list[backend.PaymentRow]                    = backend.get_unredeemed_payments_list(test.sql_conn)
            assert len(unredeemed_list)                                 == 1
            assert unredeemed_list[0].master_pkey                       == None
            assert unredeemed_list[0].status                            == base.PaymentStatus.Unredeemed
            assert unredeemed_list[0].plan                              == base.ProPlan.OneMonth
            assert unredeemed_list[0].payment_provider                  == base.PaymentProvider.iOSAppStore
            assert unredeemed_list[0].auto_renewing                     == True
            assert unredeemed_list[0].unredeemed_unix_ts_ms             == tx_info.purchaseDate
            assert unredeemed_list[0].redeemed_unix_ts_ms               == None
            assert unredeemed_list[0].expiry_unix_ts_ms                 == tx_info.expiresDate
            assert unredeemed_list[0].grace_period_duration_ms          == platform_apple.GRACE_PERIOD_DURATION_MS
            assert unredeemed_list[0].platform_refund_expiry_unix_ts_ms == 0
            assert unredeemed_list[0].revoked_unix_ts_ms                == None
            assert unredeemed_list[0].apple.original_tx_id              == tx_info.originalTransactionId
            assert unredeemed_list[0].apple.tx_id                       == tx_info.transactionId
            assert unredeemed_list[0].apple.web_line_order_tx_id        == tx_info.webOrderLineItemId

        if 1: # Did change renewal status notification
            # NOTE: Original payload (requires keys to decrypt)
            if 0:
                core:                      platform_apple.Core       = platform_apple.init()
                notification_payload_json: dict[str, base.JSONValue] = json.loads('''
                {
                  "signedPayload": "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJub3RpZmljYXRpb25UeXBlIjoiRElEX0NIQU5HRV9SRU5FV0FMX1NUQVRVUyIsInN1YnR5cGUiOiJBVVRPX1JFTkVXX0RJU0FCTEVEIiwibm90aWZpY2F0aW9uVVVJRCI6ImViYjc1MTlhLTFmOGItNDAzOC04MjI4LTViMTI1MGFiOTk4ZCIsImRhdGEiOnsiYXBwQXBwbGVJZCI6MTQ3MDE2ODg2OCwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwiYnVuZGxlVmVyc2lvbiI6IjYzNyIsImVudmlyb25tZW50IjoiU2FuZGJveCIsInNpZ25lZFRyYW5zYWN0aW9uSW5mbyI6ImV5SmhiR2NpT2lKRlV6STFOaUlzSW5nMVl5STZXeUpOU1VsRlRWUkRRMEUzWVdkQmQwbENRV2RKVVZJNFMwaDZaRzQxTlRSYUwxVnZjbUZrVG5nNWRIcEJTMEpuWjNGb2EycFBVRkZSUkVGNlFqRk5WVkYzVVdkWlJGWlJVVVJFUkhSQ1kwaENjMXBUUWxoaU0wcHpXa2hrY0ZwSFZXZFNSMVl5V2xkNGRtTkhWbmxKUmtwc1lrZEdNR0ZYT1hWamVVSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlV4TlFXdEhRVEZWUlVOM2QwTlNlbGw0UlhwQlVrSm5UbFpDUVc5TlEydEdkMk5IZUd4SlJXeDFXWGswZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOUWpSWVJGUkpNVTFFYTNoUFZFVTFUa1JSTVUxV2IxaEVWRWt6VFZSQmVFMTZSVE5PUkdONVRURnZkMmRhU1hoUlJFRXJRbWRPVmtKQlRVMU9NVUo1WWpKUloxSlZUa1JKUlRGb1dYbENRbU5JUVdkVk0xSjJZMjFWWjFsWE5XdEpSMnhWWkZjMWJHTjVRbFJrUnpsNVdsTkNVMXBYVG14aFdFSXdTVVpPY0ZveU5YQmliV040VEVSQmNVSm5UbFpDUVhOTlNUQkdkMk5IZUd4SlJtUjJZMjE0YTJReWJHdGFVMEpGV2xoYWJHSkhPWGRhV0VsblZXMVdjMWxZVW5CaU1qVjZUVkpOZDBWUldVUldVVkZMUkVGd1FtTklRbk5hVTBKS1ltMU5kVTFSYzNkRFVWbEVWbEZSUjBWM1NsWlZla0phVFVKTlIwSjVjVWRUVFRRNVFXZEZSME5EY1VkVFRUUTVRWGRGU0VFd1NVRkNUbTVXZG1oamRqZHBWQ3MzUlhnMWRFSk5RbWR5VVhOd1NIcEpjMWhTYVRCWmVHWmxhemRzZGpoM1JXMXFMMkpJYVZkMFRuZEtjV015UW05SWVuTlJhVVZxVURkTFJrbEpTMmMwV1RoNU1DOXVlVzUxUVcxcVoyZEpTVTFKU1VOQ1JFRk5RbWRPVmtoU1RVSkJaamhGUVdwQlFVMUNPRWRCTVZWa1NYZFJXVTFDWVVGR1JEaDJiRU5PVWpBeFJFcHRhV2M1TjJKQ09EVmpLMnhyUjB0YVRVaEJSME5EYzBkQlVWVkdRbmRGUWtKSFVYZFpha0YwUW1kbmNrSm5SVVpDVVdOM1FXOVphR0ZJVWpCalJHOTJUREpPYkdOdVVucE1iVVozWTBkNGJFeHRUblppVXprelpESlNlVnA2V1hWYVIxWjVUVVJGUjBORGMwZEJVVlZHUW5wQlFtaHBWbTlrU0ZKM1QyazRkbUl5VG5walF6Vm9ZMGhDYzFwVE5XcGlNakIyWWpKT2VtTkVRWHBNV0dReldraEtiazVxUVhsTlNVbENTR2RaUkZaU01HZENTVWxDUmxSRFEwRlNSWGRuWjBWT1FtZHZjV2hyYVVjNU1rNXJRbEZaUWsxSlNDdE5TVWhFUW1kbmNrSm5SVVpDVVdORFFXcERRblJuZVVKek1VcHNZa2RzYUdKdFRteEpSemwxU1VoU2IyRllUV2RaTWxaNVpFZHNiV0ZYVG1oa1IxVm5XVzVyWjFsWE5UVkpTRUpvWTI1U05VbEhSbnBqTTFaMFdsaE5aMWxYVG1wYVdFSXdXVmMxYWxwVFFuWmFhVUl3WVVkVloyUkhhR3hpYVVKb1kwaENjMkZYVG1oWmJYaHNTVWhPTUZsWE5XdFpXRXByU1VoU2JHTnRNWHBKUjBaMVdrTkNhbUl5Tld0aFdGSndZakkxZWtsSE9XMUpTRlo2V2xOM1oxa3lWbmxrUjJ4dFlWZE9hR1JIVldkalJ6bHpZVmRPTlVsSFJuVmFRMEpxV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxJUW5sWlYwNHdZVmRPYkVsSVRqQlpXRkpzWWxkV2RXUklUWFZOUkZsSFEwTnpSMEZSVlVaQ2QwbENSbWx3YjJSSVVuZFBhVGgyWkROa00weHRSbmRqUjNoc1RHMU9kbUpUT1dwYVdFb3dZVmRhY0ZreVJqQmFWMFl4WkVkb2RtTnRiREJsVXpoM1NGRlpSRlpTTUU5Q1FsbEZSa2xHYVc5SE5IZE5UVlpCTVd0MU9YcEtiVWRPVUVGV2JqTmxjVTFCTkVkQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlVVSm5iM0ZvYTJsSE9USk9hMEpuYzBKQ1FVbEdRVVJCUzBKblozRm9hMnBQVUZGUlJFRjNUbkJCUkVKdFFXcEZRU3R4V0c1U1JVTTNhRmhKVjFaTWMweDRlbTVxVW5CSmVsQm1OMVpJZWpsV0wwTlViVGdyVEVwc2NsRmxjRzV0WTFCMlIweE9ZMWcyV0ZCdWJHTm5URUZCYWtWQk5VbHFUbHBMWjJjMWNGRTNPV3R1UmpSSllsUllaRXQyT0haMWRFbEVUVmhFYldwUVZsUXpaRWQyUm5SelIxSjNXRTk1ZDFJeWExcERaRk55Wm1WdmRDSXNJazFKU1VSR2FrTkRRWEI1WjBGM1NVSkJaMGxWU1hOSGFGSjNjREJqTW01MlZUUlpVM2xqWVdaUVZHcDZZazVqZDBObldVbExiMXBKZW1vd1JVRjNUWGRhZWtWaVRVSnJSMEV4VlVWQmQzZFRVVmhDZDJKSFZXZFZiVGwyWkVOQ1JGRlRRWFJKUldONlRWTlpkMHBCV1VSV1VWRk1SRUl4UW1OSVFuTmFVMEpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJWUk5Ra1ZIUVRGVlJVTm5kMHRSV0VKM1lrZFZaMU5YTldwTWFrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmQwaG9ZMDVOYWtWM1RYcEZNMDFxUVhwT2VrVjNWMmhqVGsxNldYZE5la1UxVFVSQmQwMUVRWGRYYWtJeFRWVlJkMUZuV1VSV1VWRkVSRVIwUW1OSVFuTmFVMEpZWWpOS2MxcElaSEJhUjFWblVrZFdNbHBYZUhaalIxWjVTVVpLYkdKSFJqQmhWemwxWTNsQ1JGcFlTakJoVjFwd1dUSkdNR0ZYT1hWSlJVWXhaRWRvZG1OdGJEQmxWRVZNVFVGclIwRXhWVVZEZDNkRFVucFplRVY2UVZKQ1owNVdRa0Z2VFVOclJuZGpSM2hzU1VWc2RWbDVOSGhEZWtGS1FtZE9Wa0pCV1ZSQmJGWlVUVWhaZDBWQldVaExiMXBKZW1vd1EwRlJXVVpMTkVWRlFVTkpSRmxuUVVWaWMxRkxRemswVUhKc1YyMWFXRzVZWjNSNGVtUldTa3c0VkRCVFIxbHVaMFJTUjNCdVoyNHpUalpRVkRoS1RVVmlOMFpFYVRSaVFtMVFhRU51V2pNdmMzRTJVRVl2WTBkalMxaFhjMHcxZGs5MFpWSm9lVW8wTlhnelFWTlFOMk5QUWl0aFlXODVNR1pqY0hoVGRpOUZXa1ppYm1sQllrNW5Xa2RvU1dod1NXODBTRFpOU1VnelRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaamhEUVZGQmQwaDNXVVJXVWpCcVFrSm5kMFp2UVZWMU4wUmxiMVpuZW1sS2NXdHBjRzVsZG5JemNuSTVja3hLUzNOM1VtZFpTVXQzV1VKQ1VWVklRVkZGUlU5cVFUUk5SRmxIUTBOelIwRlJWVVpDZWtGQ2FHbHdiMlJJVW5kUGFUaDJZakpPZW1ORE5XaGpTRUp6V2xNMWFtSXlNSFppTWs1NlkwUkJla3hYUm5kalIzaHNZMjA1ZG1SSFRtaGFlazEzVG5kWlJGWlNNR1pDUkVGM1RHcEJjMjlEY1dkTFNWbHRZVWhTTUdORWIzWk1NazU1WWtNMWFHTklRbk5hVXpWcVlqSXdkbGxZUW5kaVIxWjVZakk1TUZreVJtNU5lVFZxWTIxM2QwaFJXVVJXVWpCUFFrSlpSVVpFT0hac1EwNVNNREZFU20xcFp6azNZa0k0TldNcmJHdEhTMXBOUVRSSFFURlZaRVIzUlVJdmQxRkZRWGRKUWtKcVFWRkNaMjl4YUd0cFJ6a3lUbXRDWjBsQ1FrRkpSa0ZFUVV0Q1oyZHhhR3RxVDFCUlVVUkJkMDV2UVVSQ2JFRnFRa0ZZYUZOeE5VbDVTMjluVFVOUWRIYzBPVEJDWVVJMk56ZERZVVZIU2xoMVpsRkNMMFZ4V2tka05rTlRhbWxEZEU5dWRVMVVZbGhXV0cxNGVHTjRabXREVFZGRVZGTlFlR0Z5V2xoMlRuSnJlRlV6Vkd0VlRVa3pNM2w2ZGtaV1ZsSlVOSGQ0VjBwRE9UazBUM05rWTFvMEsxSkhUbk5aUkhsU05XZHRaSEl3YmtSSFp6MGlMQ0pOU1VsRFVYcERRMEZqYldkQmQwbENRV2RKU1V4aldEaHBUa3hHVXpWVmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhkYWVrVmlUVUpyUjBFeFZVVkJkM2RUVVZoQ2QySkhWV2RWYlRsMlpFTkNSRkZUUVhSSlJXTjZUVk5aZDBwQldVUldVVkZNUkVJeFFtTklRbk5hVTBKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVlJOUWtWSFFURlZSVU5uZDB0UldFSjNZa2RWWjFOWE5XcE1ha1ZNVFVGclIwRXhWVVZDYUUxRFZsWk5kMGhvWTA1TlZGRjNUa1JOZDAxVVozaFBWRUV5VjJoalRrMTZhM2RPUkUxM1RWUm5lRTlVUVRKWGFrSnVUVkp6ZDBkUldVUldVVkZFUkVKS1FtTklRbk5hVTBKVFlqSTVNRWxGVGtKSlF6Qm5VbnBOZUVwcVFXdENaMDVXUWtGelRVaFZSbmRqUjNoc1NVVk9iR051VW5CYWJXeHFXVmhTY0dJeU5HZFJXRll3WVVjNWVXRllValZOVWsxM1JWRlpSRlpSVVV0RVFYQkNZMGhDYzFwVFFrcGliVTExVFZGemQwTlJXVVJXVVZGSFJYZEtWbFY2UWpKTlFrRkhRbmx4UjFOTk5EbEJaMFZIUWxOMVFrSkJRV2xCTWtsQlFrcHFjRXg2TVVGamNWUjBhM2xLZVdkU1RXTXpVa05XT0dOWGFsUnVTR05HUW1KYVJIVlhiVUpUY0ROYVNIUm1WR3BxVkhWNGVFVjBXQzh4U0RkWmVWbHNNMG8yV1ZKaVZIcENVRVZXYjBFdlZtaFpSRXRZTVVSNWVFNUNNR05VWkdSeFdHdzFaSFpOVm5wMFN6VXhOMGxFZGxsMVZsUmFXSEJ0YTA5c1JVdE5ZVTVEVFVWQmQwaFJXVVJXVWpCUFFrSlpSVVpNZFhjemNVWlpUVFJwWVhCSmNWb3pjalk1TmpZdllYbDVVM0pOUVRoSFFURlZaRVYzUlVJdmQxRkdUVUZOUWtGbU9IZEVaMWxFVmxJd1VFRlJTQzlDUVZGRVFXZEZSMDFCYjBkRFEzRkhVMDAwT1VKQlRVUkJNbWRCVFVkVlEwMVJRMFEyWTBoRlJtdzBZVmhVVVZreVpUTjJPVWQzVDBGRldreDFUaXQ1VW1oSVJrUXZNMjFsYjNsb2NHMTJUM2RuVUZWdVVGZFVlRzVUTkdGMEszRkplRlZEVFVjeGJXbG9SRXN4UVROVlZEZ3lUbEY2TmpCcGJVOXNUVEkzYW1Ka2IxaDBNbEZtZVVaTmJTdFphR2xrUkd0TVJqRjJURlZoWjAwMlFtZEVOVFpMZVV0QlBUMGlYWDAuZXlKMGNtRnVjMkZqZEdsdmJrbGtJam9pTWpBd01EQXdNVEF5TlRZNE5qTXhNeUlzSW05eWFXZHBibUZzVkhKaGJuTmhZM1JwYjI1SlpDSTZJakl3TURBd01ERXdNalE1T1RNeU9Ua2lMQ0ozWldKUGNtUmxja3hwYm1WSmRHVnRTV1FpT2lJeU1EQXdNREF3TVRFek9EUTBOekEySWl3aVluVnVaR3hsU1dRaU9pSmpiMjB1Ykc5cmFTMXdjbTlxWldOMExteHZhMmt0YldWemMyVnVaMlZ5SWl3aWNISnZaSFZqZEVsa0lqb2lZMjl0TG1kbGRITmxjM05wYjI0dWIzSm5MbkJ5YjE5emRXSWlMQ0p6ZFdKelkzSnBjSFJwYjI1SGNtOTFjRWxrWlc1MGFXWnBaWElpT2lJeU1UYzFNamd4TkNJc0luQjFjbU5vWVhObFJHRjBaU0k2TVRjMU9UTTRPRGMyTnpBd01Dd2liM0pwWjJsdVlXeFFkWEpqYUdGelpVUmhkR1VpT2pFM05Ua3pNREU0TXpNd01EQXNJbVY0Y0dseVpYTkVZWFJsSWpveE56VTVNemc0T1RRM01EQXdMQ0p4ZFdGdWRHbDBlU0k2TVN3aWRIbHdaU0k2SWtGMWRHOHRVbVZ1WlhkaFlteGxJRk4xWW5OamNtbHdkR2x2YmlJc0ltbHVRWEJ3VDNkdVpYSnphR2x3Vkhsd1pTSTZJbEJWVWtOSVFWTkZSQ0lzSW5OcFoyNWxaRVJoZEdVaU9qRTNOVGt6T0RnNE5UVTBOek1zSW1WdWRtbHliMjV0Wlc1MElqb2lVMkZ1WkdKdmVDSXNJblJ5WVc1ellXTjBhVzl1VW1WaGMyOXVJam9pVUZWU1EwaEJVMFVpTENKemRHOXlaV1p5YjI1MElqb2lRVlZUSWl3aWMzUnZjbVZtY205dWRFbGtJam9pTVRRek5EWXdJaXdpY0hKcFkyVWlPakU1T1RBc0ltTjFjbkpsYm1ONUlqb2lRVlZFSWl3aVlYQndWSEpoYm5OaFkzUnBiMjVKWkNJNklqY3dORGc1TnpRMk9Ua3dNek00TXpreE9TSjkuOWRqUmpwbmNQU1ViQWFwR0ZZeEltT2pleDQ3SlhLVXFRVE9XbHZ1QXdvSjhIdk1sRTRMY2lWWk5NWE41LUw3RjNDRXdtU3l3VTYyUGZwWWE2bTZFaUEiLCJzaWduZWRSZW5ld2FsSW5mbyI6ImV5SmhiR2NpT2lKRlV6STFOaUlzSW5nMVl5STZXeUpOU1VsRlRWUkRRMEUzWVdkQmQwbENRV2RKVVZJNFMwaDZaRzQxTlRSYUwxVnZjbUZrVG5nNWRIcEJTMEpuWjNGb2EycFBVRkZSUkVGNlFqRk5WVkYzVVdkWlJGWlJVVVJFUkhSQ1kwaENjMXBUUWxoaU0wcHpXa2hrY0ZwSFZXZFNSMVl5V2xkNGRtTkhWbmxKUmtwc1lrZEdNR0ZYT1hWamVVSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlV4TlFXdEhRVEZWUlVOM2QwTlNlbGw0UlhwQlVrSm5UbFpDUVc5TlEydEdkMk5IZUd4SlJXeDFXWGswZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOUWpSWVJGUkpNVTFFYTNoUFZFVTFUa1JSTVUxV2IxaEVWRWt6VFZSQmVFMTZSVE5PUkdONVRURnZkMmRhU1hoUlJFRXJRbWRPVmtKQlRVMU9NVUo1WWpKUloxSlZUa1JKUlRGb1dYbENRbU5JUVdkVk0xSjJZMjFWWjFsWE5XdEpSMnhWWkZjMWJHTjVRbFJrUnpsNVdsTkNVMXBYVG14aFdFSXdTVVpPY0ZveU5YQmliV040VEVSQmNVSm5UbFpDUVhOTlNUQkdkMk5IZUd4SlJtUjJZMjE0YTJReWJHdGFVMEpGV2xoYWJHSkhPWGRhV0VsblZXMVdjMWxZVW5CaU1qVjZUVkpOZDBWUldVUldVVkZMUkVGd1FtTklRbk5hVTBKS1ltMU5kVTFSYzNkRFVWbEVWbEZSUjBWM1NsWlZla0phVFVKTlIwSjVjVWRUVFRRNVFXZEZSME5EY1VkVFRUUTVRWGRGU0VFd1NVRkNUbTVXZG1oamRqZHBWQ3MzUlhnMWRFSk5RbWR5VVhOd1NIcEpjMWhTYVRCWmVHWmxhemRzZGpoM1JXMXFMMkpJYVZkMFRuZEtjV015UW05SWVuTlJhVVZxVURkTFJrbEpTMmMwV1RoNU1DOXVlVzUxUVcxcVoyZEpTVTFKU1VOQ1JFRk5RbWRPVmtoU1RVSkJaamhGUVdwQlFVMUNPRWRCTVZWa1NYZFJXVTFDWVVGR1JEaDJiRU5PVWpBeFJFcHRhV2M1TjJKQ09EVmpLMnhyUjB0YVRVaEJSME5EYzBkQlVWVkdRbmRGUWtKSFVYZFpha0YwUW1kbmNrSm5SVVpDVVdOM1FXOVphR0ZJVWpCalJHOTJUREpPYkdOdVVucE1iVVozWTBkNGJFeHRUblppVXprelpESlNlVnA2V1hWYVIxWjVUVVJGUjBORGMwZEJVVlZHUW5wQlFtaHBWbTlrU0ZKM1QyazRkbUl5VG5walF6Vm9ZMGhDYzFwVE5XcGlNakIyWWpKT2VtTkVRWHBNV0dReldraEtiazVxUVhsTlNVbENTR2RaUkZaU01HZENTVWxDUmxSRFEwRlNSWGRuWjBWT1FtZHZjV2hyYVVjNU1rNXJRbEZaUWsxSlNDdE5TVWhFUW1kbmNrSm5SVVpDVVdORFFXcERRblJuZVVKek1VcHNZa2RzYUdKdFRteEpSemwxU1VoU2IyRllUV2RaTWxaNVpFZHNiV0ZYVG1oa1IxVm5XVzVyWjFsWE5UVkpTRUpvWTI1U05VbEhSbnBqTTFaMFdsaE5aMWxYVG1wYVdFSXdXVmMxYWxwVFFuWmFhVUl3WVVkVloyUkhhR3hpYVVKb1kwaENjMkZYVG1oWmJYaHNTVWhPTUZsWE5XdFpXRXByU1VoU2JHTnRNWHBKUjBaMVdrTkNhbUl5Tld0aFdGSndZakkxZWtsSE9XMUpTRlo2V2xOM1oxa3lWbmxrUjJ4dFlWZE9hR1JIVldkalJ6bHpZVmRPTlVsSFJuVmFRMEpxV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxJUW5sWlYwNHdZVmRPYkVsSVRqQlpXRkpzWWxkV2RXUklUWFZOUkZsSFEwTnpSMEZSVlVaQ2QwbENSbWx3YjJSSVVuZFBhVGgyWkROa00weHRSbmRqUjNoc1RHMU9kbUpUT1dwYVdFb3dZVmRhY0ZreVJqQmFWMFl4WkVkb2RtTnRiREJsVXpoM1NGRlpSRlpTTUU5Q1FsbEZSa2xHYVc5SE5IZE5UVlpCTVd0MU9YcEtiVWRPVUVGV2JqTmxjVTFCTkVkQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlVVSm5iM0ZvYTJsSE9USk9hMEpuYzBKQ1FVbEdRVVJCUzBKblozRm9hMnBQVUZGUlJFRjNUbkJCUkVKdFFXcEZRU3R4V0c1U1JVTTNhRmhKVjFaTWMweDRlbTVxVW5CSmVsQm1OMVpJZWpsV0wwTlViVGdyVEVwc2NsRmxjRzV0WTFCMlIweE9ZMWcyV0ZCdWJHTm5URUZCYWtWQk5VbHFUbHBMWjJjMWNGRTNPV3R1UmpSSllsUllaRXQyT0haMWRFbEVUVmhFYldwUVZsUXpaRWQyUm5SelIxSjNXRTk1ZDFJeWExcERaRk55Wm1WdmRDSXNJazFKU1VSR2FrTkRRWEI1WjBGM1NVSkJaMGxWU1hOSGFGSjNjREJqTW01MlZUUlpVM2xqWVdaUVZHcDZZazVqZDBObldVbExiMXBKZW1vd1JVRjNUWGRhZWtWaVRVSnJSMEV4VlVWQmQzZFRVVmhDZDJKSFZXZFZiVGwyWkVOQ1JGRlRRWFJKUldONlRWTlpkMHBCV1VSV1VWRk1SRUl4UW1OSVFuTmFVMEpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJWUk5Ra1ZIUVRGVlJVTm5kMHRSV0VKM1lrZFZaMU5YTldwTWFrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmQwaG9ZMDVOYWtWM1RYcEZNMDFxUVhwT2VrVjNWMmhqVGsxNldYZE5la1UxVFVSQmQwMUVRWGRYYWtJeFRWVlJkMUZuV1VSV1VWRkVSRVIwUW1OSVFuTmFVMEpZWWpOS2MxcElaSEJhUjFWblVrZFdNbHBYZUhaalIxWjVTVVpLYkdKSFJqQmhWemwxWTNsQ1JGcFlTakJoVjFwd1dUSkdNR0ZYT1hWSlJVWXhaRWRvZG1OdGJEQmxWRVZNVFVGclIwRXhWVVZEZDNkRFVucFplRVY2UVZKQ1owNVdRa0Z2VFVOclJuZGpSM2hzU1VWc2RWbDVOSGhEZWtGS1FtZE9Wa0pCV1ZSQmJGWlVUVWhaZDBWQldVaExiMXBKZW1vd1EwRlJXVVpMTkVWRlFVTkpSRmxuUVVWaWMxRkxRemswVUhKc1YyMWFXRzVZWjNSNGVtUldTa3c0VkRCVFIxbHVaMFJTUjNCdVoyNHpUalpRVkRoS1RVVmlOMFpFYVRSaVFtMVFhRU51V2pNdmMzRTJVRVl2WTBkalMxaFhjMHcxZGs5MFpWSm9lVW8wTlhnelFWTlFOMk5QUWl0aFlXODVNR1pqY0hoVGRpOUZXa1ppYm1sQllrNW5Xa2RvU1dod1NXODBTRFpOU1VnelRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaamhEUVZGQmQwaDNXVVJXVWpCcVFrSm5kMFp2UVZWMU4wUmxiMVpuZW1sS2NXdHBjRzVsZG5JemNuSTVja3hLUzNOM1VtZFpTVXQzV1VKQ1VWVklRVkZGUlU5cVFUUk5SRmxIUTBOelIwRlJWVVpDZWtGQ2FHbHdiMlJJVW5kUGFUaDJZakpPZW1ORE5XaGpTRUp6V2xNMWFtSXlNSFppTWs1NlkwUkJla3hYUm5kalIzaHNZMjA1ZG1SSFRtaGFlazEzVG5kWlJGWlNNR1pDUkVGM1RHcEJjMjlEY1dkTFNWbHRZVWhTTUdORWIzWk1NazU1WWtNMWFHTklRbk5hVXpWcVlqSXdkbGxZUW5kaVIxWjVZakk1TUZreVJtNU5lVFZxWTIxM2QwaFJXVVJXVWpCUFFrSlpSVVpFT0hac1EwNVNNREZFU20xcFp6azNZa0k0TldNcmJHdEhTMXBOUVRSSFFURlZaRVIzUlVJdmQxRkZRWGRKUWtKcVFWRkNaMjl4YUd0cFJ6a3lUbXRDWjBsQ1FrRkpSa0ZFUVV0Q1oyZHhhR3RxVDFCUlVVUkJkMDV2UVVSQ2JFRnFRa0ZZYUZOeE5VbDVTMjluVFVOUWRIYzBPVEJDWVVJMk56ZERZVVZIU2xoMVpsRkNMMFZ4V2tka05rTlRhbWxEZEU5dWRVMVVZbGhXV0cxNGVHTjRabXREVFZGRVZGTlFlR0Z5V2xoMlRuSnJlRlV6Vkd0VlRVa3pNM2w2ZGtaV1ZsSlVOSGQ0VjBwRE9UazBUM05rWTFvMEsxSkhUbk5aUkhsU05XZHRaSEl3YmtSSFp6MGlMQ0pOU1VsRFVYcERRMEZqYldkQmQwbENRV2RKU1V4aldEaHBUa3hHVXpWVmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhkYWVrVmlUVUpyUjBFeFZVVkJkM2RUVVZoQ2QySkhWV2RWYlRsMlpFTkNSRkZUUVhSSlJXTjZUVk5aZDBwQldVUldVVkZNUkVJeFFtTklRbk5hVTBKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVlJOUWtWSFFURlZSVU5uZDB0UldFSjNZa2RWWjFOWE5XcE1ha1ZNVFVGclIwRXhWVVZDYUUxRFZsWk5kMGhvWTA1TlZGRjNUa1JOZDAxVVozaFBWRUV5VjJoalRrMTZhM2RPUkUxM1RWUm5lRTlVUVRKWGFrSnVUVkp6ZDBkUldVUldVVkZFUkVKS1FtTklRbk5hVTBKVFlqSTVNRWxGVGtKSlF6Qm5VbnBOZUVwcVFXdENaMDVXUWtGelRVaFZSbmRqUjNoc1NVVk9iR051VW5CYWJXeHFXVmhTY0dJeU5HZFJXRll3WVVjNWVXRllValZOVWsxM1JWRlpSRlpSVVV0RVFYQkNZMGhDYzFwVFFrcGliVTExVFZGemQwTlJXVVJXVVZGSFJYZEtWbFY2UWpKTlFrRkhRbmx4UjFOTk5EbEJaMFZIUWxOMVFrSkJRV2xCTWtsQlFrcHFjRXg2TVVGamNWUjBhM2xLZVdkU1RXTXpVa05XT0dOWGFsUnVTR05HUW1KYVJIVlhiVUpUY0ROYVNIUm1WR3BxVkhWNGVFVjBXQzh4U0RkWmVWbHNNMG8yV1ZKaVZIcENVRVZXYjBFdlZtaFpSRXRZTVVSNWVFNUNNR05VWkdSeFdHdzFaSFpOVm5wMFN6VXhOMGxFZGxsMVZsUmFXSEJ0YTA5c1JVdE5ZVTVEVFVWQmQwaFJXVVJXVWpCUFFrSlpSVVpNZFhjemNVWlpUVFJwWVhCSmNWb3pjalk1TmpZdllYbDVVM0pOUVRoSFFURlZaRVYzUlVJdmQxRkdUVUZOUWtGbU9IZEVaMWxFVmxJd1VFRlJTQzlDUVZGRVFXZEZSMDFCYjBkRFEzRkhVMDAwT1VKQlRVUkJNbWRCVFVkVlEwMVJRMFEyWTBoRlJtdzBZVmhVVVZreVpUTjJPVWQzVDBGRldreDFUaXQ1VW1oSVJrUXZNMjFsYjNsb2NHMTJUM2RuVUZWdVVGZFVlRzVUTkdGMEszRkplRlZEVFVjeGJXbG9SRXN4UVROVlZEZ3lUbEY2TmpCcGJVOXNUVEkzYW1Ka2IxaDBNbEZtZVVaTmJTdFphR2xrUkd0TVJqRjJURlZoWjAwMlFtZEVOVFpMZVV0QlBUMGlYWDAuZXlKdmNtbG5hVzVoYkZSeVlXNXpZV04wYVc5dVNXUWlPaUl5TURBd01EQXhNREkwT1Rrek1qazVJaXdpWVhWMGIxSmxibVYzVUhKdlpIVmpkRWxrSWpvaVkyOXRMbWRsZEhObGMzTnBiMjR1YjNKbkxuQnliMTl6ZFdJaUxDSndjbTlrZFdOMFNXUWlPaUpqYjIwdVoyVjBjMlZ6YzJsdmJpNXZjbWN1Y0hKdlgzTjFZaUlzSW1GMWRHOVNaVzVsZDFOMFlYUjFjeUk2TUN3aWMybG5ibVZrUkdGMFpTSTZNVGMxT1RNNE9EZzFOVFEzTXl3aVpXNTJhWEp2Ym0xbGJuUWlPaUpUWVc1a1ltOTRJaXdpY21WalpXNTBVM1ZpYzJOeWFYQjBhVzl1VTNSaGNuUkVZWFJsSWpveE56VTVNemc0TnpZM01EQXdMQ0p5Wlc1bGQyRnNSR0YwWlNJNk1UYzFPVE00T0RrME56QXdNQ3dpWVhCd1ZISmhibk5oWTNScGIyNUpaQ0k2SWpjd05EZzVOelEyT1Rrd016TTRNemt4T1NKOS5QUVNYTjkySVVaamdQUDBXRzhTaWlZdDhQSjFwZ1JyNUUzcDJKRTczZ1gyVnUzbHJPSkVIaDMzazgwNVg3X08tSzgwcWJ2SVdTOUtpdlY0RkoxQkRUQSIsInN0YXR1cyI6MX0sInZlcnNpb24iOiIyLjAiLCJzaWduZWREYXRlIjoxNzU5Mzg4ODU1NDczfQ.XUQflkEJcQl3R57ht_RHxMWCIfxmfO3LxVgwsXRyjBSVzfAtjGo9X1WwnASdUL1PO1TkmRtz8QhFyiCk3nDU_g"
                }
                ''')

                signed_payload: str = typing.cast(str, notification_payload_json['signedPayload'])
                body: AppleResponseBodyV2DecodedPayload = core.signed_data_verifier.verify_and_decode_notification(signed_payload)
                dump_apple_signed_payloads(core, body)

            # NOTE: Generated by dump_apple_signed_payloads
            # NOTE: Signed Payload
            body                                     = AppleResponseBodyV2DecodedPayload()
            body_data                                = AppleData()
            body_data.appAppleId                     = 1470168868
            body_data.bundleId                       = 'com.loki-project.loki-messenger'
            body_data.bundleVersion                  = '637'
            body_data.consumptionRequestReason       = None
            body_data.environment                    = AppleEnvironment.SANDBOX
            body_data.rawConsumptionRequestReason    = None
            body_data.rawEnvironment                 = 'Sandbox'
            body_data.rawStatus                      = 1
            body_data.signedRenewalInfo              = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MCwic2lnbmVkRGF0ZSI6MTc1OTM4ODg1NTQ3MywiZW52aXJvbm1lbnQiOiJTYW5kYm94IiwicmVjZW50U3Vic2NyaXB0aW9uU3RhcnREYXRlIjoxNzU5Mzg4NzY3MDAwLCJyZW5ld2FsRGF0ZSI6MTc1OTM4ODk0NzAwMCwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.PQSXN92IUZjgPP0WG8SiiYt8PJ1pgRr5E3p2JE73gX2Vu3lrOJEHh33k805X7_O-K80qbvIWS9KivV4FJ1BDTA'
            body_data.signedTransactionInfo          = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNTY4NjMxMyIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTEzODQ0NzA2IiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTM4ODc2NzAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5Mzg4OTQ3MDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTkzODg4NTU0NzMsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.9djRjpncPSUbAapGFYxImOjex47JXKUqQTOWlvuAwoJ8HvMlE4LciVZNMXN5-L7F3CEwmSywU62PfpYa6m6EiA'
            body_data.status                         = AppleStatus.ACTIVE
            body.data                                = body_data
            body.externalPurchaseToken               = None
            body.notificationType                    = AppleNotificationTypeV2.DID_CHANGE_RENEWAL_STATUS
            body.notificationUUID                    = 'ebb7519a-1f8b-4038-8228-5b1250ab998d'
            body.rawNotificationType                 = 'DID_CHANGE_RENEWAL_STATUS'
            body.rawSubtype                          = 'AUTO_RENEW_DISABLED'
            body.signedDate                          = 1759388855473
            body.subtype                             = AppleSubtype.AUTO_RENEW_DISABLED
            body.summary                             = None
            body.version                             = '2.0'

            # NOTE: Signed Renewal Info
            renewal_info                             = AppleJWSRenewalInfoDecodedPayload()
            renewal_info.appAccountToken             = None
            renewal_info.appTransactionId            = '704897469903383919'
            renewal_info.autoRenewProductId          = None
            renewal_info.autoRenewStatus             = None
            renewal_info.currency                    = 'AUD'
            renewal_info.eligibleWinBackOfferIds     = None
            renewal_info.environment                 = AppleEnvironment.SANDBOX
            renewal_info.expirationIntent            = None
            renewal_info.gracePeriodExpiresDate      = None
            renewal_info.isInBillingRetryPeriod      = None
            renewal_info.offerDiscountType           = None
            renewal_info.offerIdentifier             = None
            renewal_info.offerPeriod                 = None
            renewal_info.offerType                   = None
            renewal_info.originalTransactionId       = '2000001024993299'
            renewal_info.priceIncreaseStatus         = None
            renewal_info.productId                   = 'com.getsession.org.pro_sub'
            renewal_info.rawAutoRenewStatus          = None
            renewal_info.rawEnvironment              = 'Sandbox'
            renewal_info.rawExpirationIntent         = None
            renewal_info.rawOfferDiscountType        = None
            renewal_info.rawOfferType                = None
            renewal_info.rawPriceIncreaseStatus      = None
            renewal_info.recentSubscriptionStartDate = None
            renewal_info.renewalDate                 = None
            renewal_info.renewalPrice                = None
            renewal_info.signedDate                  = 1759388855473

            # NOTE: Signed Transaction Info
            tx_info                                  = AppleJWSTransactionDecodedPayload()
            tx_info.appAccountToken                  = None
            tx_info.appTransactionId                 = '704897469903383919'
            tx_info.bundleId                         = 'com.loki-project.loki-messenger'
            tx_info.currency                         = 'AUD'
            tx_info.environment                      = AppleEnvironment.SANDBOX
            tx_info.expiresDate                      = 1759388947000
            tx_info.inAppOwnershipType               = AppleInAppOwnershipType.PURCHASED
            tx_info.isUpgraded                       = None
            tx_info.offerDiscountType                = None
            tx_info.offerIdentifier                  = None
            tx_info.offerPeriod                      = None
            tx_info.offerType                        = None
            tx_info.originalPurchaseDate             = 1759301833000
            tx_info.originalTransactionId            = '2000001024993299'
            tx_info.price                            = 1990
            tx_info.productId                        = 'com.getsession.org.pro_sub'
            tx_info.purchaseDate                     = 1759388767000
            tx_info.quantity                         = 1
            tx_info.rawEnvironment                   = 'Sandbox'
            tx_info.rawInAppOwnershipType            = 'PURCHASED'
            tx_info.rawOfferDiscountType             = None
            tx_info.rawOfferType                     = None
            tx_info.rawRevocationReason              = None
            tx_info.rawTransactionReason             = 'PURCHASE'
            tx_info.rawType                          = 'Auto-Renewable Subscription'
            tx_info.revocationDate                   = None
            tx_info.revocationReason                 = None
            tx_info.signedDate                       = 1759388855473
            tx_info.storefront                       = 'AUS'
            tx_info.storefrontId                     = '143460'
            tx_info.subscriptionGroupIdentifier      = '21752814'
            tx_info.transactionId                    = '2000001025686313'
            tx_info.transactionReason                = AppleTransactionReason.PURCHASE
            tx_info.type                             = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
            tx_info.webOrderLineItemId               = '2000000113844706'

            decoded_notification                     = platform_apple.DecodedNotification(body=body, tx_info=tx_info, renewal_info=renewal_info)

            err = base.ErrorSink()
            platform_apple.handle_notification(decoded_notification=decoded_notification, sql_conn=test.sql_conn, err=err)
            assert not err.has(), err.msg_list

            # NOTE: Check payment is still in the DB and that auto-renewing was turned off
            payment_list: list[backend.PaymentRow]                    = backend.get_payments_list(test.sql_conn)
            assert len(payment_list)                                 == 1
            assert payment_list[0].master_pkey                       == None
            assert payment_list[0].status                            == base.PaymentStatus.Unredeemed
            assert payment_list[0].plan                              == base.ProPlan.OneMonth
            assert payment_list[0].payment_provider                  == base.PaymentProvider.iOSAppStore
            assert payment_list[0].auto_renewing                     == False
            assert payment_list[0].unredeemed_unix_ts_ms             == tx_info.purchaseDate
            assert payment_list[0].redeemed_unix_ts_ms               == None
            assert payment_list[0].expiry_unix_ts_ms                 == tx_info.expiresDate
            assert payment_list[0].grace_period_duration_ms          == platform_apple.GRACE_PERIOD_DURATION_MS
            assert payment_list[0].platform_refund_expiry_unix_ts_ms == 0
            assert payment_list[0].revoked_unix_ts_ms                == None
            assert payment_list[0].apple.original_tx_id              == tx_info.originalTransactionId
            assert payment_list[0].apple.tx_id                       == tx_info.transactionId
            assert payment_list[0].apple.web_line_order_tx_id        == tx_info.webOrderLineItemId

        if 1: # Expire (voluntary) notification
            # NOTE: Original payload (requires keys to decrypt)
            if 0:
                core:                      platform_apple.Core       = platform_apple.init()
                notification_payload_json: dict[str, base.JSONValue] = json.loads('''
                {
                  "signedPayload": "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJub3RpZmljYXRpb25UeXBlIjoiRVhQSVJFRCIsInN1YnR5cGUiOiJWT0xVTlRBUlkiLCJub3RpZmljYXRpb25VVUlEIjoiYzc3MjYyOTgtMzJlYi00OGY3LTk2MjMtMDk3ZmY2ZGU0ZDY5IiwiZGF0YSI6eyJhcHBBcHBsZUlkIjoxNDcwMTY4ODY4LCJidW5kbGVJZCI6ImNvbS5sb2tpLXByb2plY3QubG9raS1tZXNzZW5nZXIiLCJidW5kbGVWZXJzaW9uIjoiNjM3IiwiZW52aXJvbm1lbnQiOiJTYW5kYm94Iiwic2lnbmVkVHJhbnNhY3Rpb25JbmZvIjoiZXlKaGJHY2lPaUpGVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxGVFZSRFEwRTNZV2RCZDBsQ1FXZEpVVkk0UzBoNlpHNDFOVFJhTDFWdmNtRmtUbmc1ZEhwQlMwSm5aM0ZvYTJwUFVGRlJSRUY2UWpGTlZWRjNVV2RaUkZaUlVVUkVSSFJDWTBoQ2MxcFRRbGhpTTBweldraGtjRnBIVldkU1IxWXlXbGQ0ZG1OSFZubEpSa3BzWWtkR01HRlhPWFZqZVVKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVXhOUVd0SFFURlZSVU4zZDBOU2VsbDRSWHBCVWtKblRsWkNRVzlOUTJ0R2QyTkhlR3hKUld4MVdYazBlRU42UVVwQ1owNVdRa0ZaVkVGc1ZsUk5RalJZUkZSSk1VMUVhM2hQVkVVMVRrUlJNVTFXYjFoRVZFa3pUVlJCZUUxNlJUTk9SR041VFRGdmQyZGFTWGhSUkVFclFtZE9Wa0pCVFUxT01VSjVZakpSWjFKVlRrUkpSVEZvV1hsQ1FtTklRV2RWTTFKMlkyMVZaMWxYTld0SlIyeFZaRmMxYkdONVFsUmtSemw1V2xOQ1UxcFhUbXhoV0VJd1NVWk9jRm95TlhCaWJXTjRURVJCY1VKblRsWkNRWE5OU1RCR2QyTkhlR3hKUm1SMlkyMTRhMlF5Ykd0YVUwSkZXbGhhYkdKSE9YZGFXRWxuVlcxV2MxbFlVbkJpTWpWNlRWSk5kMFZSV1VSV1VWRkxSRUZ3UW1OSVFuTmFVMEpLWW0xTmRVMVJjM2REVVZsRVZsRlJSMFYzU2xaVmVrSmFUVUpOUjBKNWNVZFRUVFE1UVdkRlIwTkRjVWRUVFRRNVFYZEZTRUV3U1VGQ1RtNVdkbWhqZGpkcFZDczNSWGcxZEVKTlFtZHlVWE53U0hwSmMxaFNhVEJaZUdabGF6ZHNkamgzUlcxcUwySklhVmQwVG5kS2NXTXlRbTlJZW5OUmFVVnFVRGRMUmtsSlMyYzBXVGg1TUM5dWVXNTFRVzFxWjJkSlNVMUpTVU5DUkVGTlFtZE9Wa2hTVFVKQlpqaEZRV3BCUVUxQ09FZEJNVlZrU1hkUldVMUNZVUZHUkRoMmJFTk9VakF4UkVwdGFXYzVOMkpDT0RWaksyeHJSMHRhVFVoQlIwTkRjMGRCVVZWR1FuZEZRa0pIVVhkWmFrRjBRbWRuY2tKblJVWkNVV04zUVc5WmFHRklVakJqUkc5MlRESk9iR051VW5wTWJVWjNZMGQ0YkV4dFRuWmlVemt6WkRKU2VWcDZXWFZhUjFaNVRVUkZSME5EYzBkQlVWVkdRbnBCUW1ocFZtOWtTRkozVDJrNGRtSXlUbnBqUXpWb1kwaENjMXBUTldwaU1qQjJZakpPZW1ORVFYcE1XR1F6V2toS2JrNXFRWGxOU1VsQ1NHZFpSRlpTTUdkQ1NVbENSbFJEUTBGU1JYZG5aMFZPUW1kdmNXaHJhVWM1TWs1clFsRlpRazFKU0N0TlNVaEVRbWRuY2tKblJVWkNVV05EUVdwRFFuUm5lVUp6TVVwc1lrZHNhR0p0VG14SlJ6bDFTVWhTYjJGWVRXZFpNbFo1WkVkc2JXRlhUbWhrUjFWbldXNXJaMWxYTlRWSlNFSm9ZMjVTTlVsSFJucGpNMVowV2xoTloxbFhUbXBhV0VJd1dWYzFhbHBUUW5aYWFVSXdZVWRWWjJSSGFHeGlhVUpvWTBoQ2MyRlhUbWhaYlhoc1NVaE9NRmxYTld0WldFcHJTVWhTYkdOdE1YcEpSMFoxV2tOQ2FtSXlOV3RoV0ZKd1lqSTFla2xIT1cxSlNGWjZXbE4zWjFreVZubGtSMnh0WVZkT2FHUkhWV2RqUnpsellWZE9OVWxIUm5WYVEwSnFXbGhLTUdGWFduQlpNa1l3WVZjNWRVbElRbmxaVjA0d1lWZE9iRWxJVGpCWldGSnNZbGRXZFdSSVRYVk5SRmxIUTBOelIwRlJWVVpDZDBsQ1JtbHdiMlJJVW5kUGFUaDJaRE5rTTB4dFJuZGpSM2hzVEcxT2RtSlRPV3BhV0Vvd1lWZGFjRmt5UmpCYVYwWXhaRWRvZG1OdGJEQmxVemgzU0ZGWlJGWlNNRTlDUWxsRlJrbEdhVzlITkhkTlRWWkJNV3QxT1hwS2JVZE9VRUZXYmpObGNVMUJORWRCTVZWa1JIZEZRaTkzVVVWQmQwbElaMFJCVVVKbmIzRm9hMmxIT1RKT2EwSm5jMEpDUVVsR1FVUkJTMEpuWjNGb2EycFBVRkZSUkVGM1RuQkJSRUp0UVdwRlFTdHhXRzVTUlVNM2FGaEpWMVpNYzB4NGVtNXFVbkJKZWxCbU4xWkllamxXTDBOVWJUZ3JURXBzY2xGbGNHNXRZMUIyUjB4T1kxZzJXRkJ1YkdOblRFRkJha1ZCTlVscVRscExaMmMxY0ZFM09XdHVSalJKWWxSWVpFdDJPSFoxZEVsRVRWaEViV3BRVmxRelpFZDJSblJ6UjFKM1dFOTVkMUl5YTFwRFpGTnlabVZ2ZENJc0lrMUpTVVJHYWtORFFYQjVaMEYzU1VKQlowbFZTWE5IYUZKM2NEQmpNbTUyVlRSWlUzbGpZV1pRVkdwNllrNWpkME5uV1VsTGIxcEplbW93UlVGM1RYZGFla1ZpVFVKclIwRXhWVVZCZDNkVFVWaENkMkpIVldkVmJUbDJaRU5DUkZGVFFYUkpSV042VFZOWmQwcEJXVVJXVVZGTVJFSXhRbU5JUW5OYVUwSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlZSTlFrVkhRVEZWUlVObmQwdFJXRUozWWtkVloxTlhOV3BNYWtWTVRVRnJSMEV4VlVWQ2FFMURWbFpOZDBob1kwNU5ha1YzVFhwRk0wMXFRWHBPZWtWM1YyaGpUazE2V1hkTmVrVTFUVVJCZDAxRVFYZFhha0l4VFZWUmQxRm5XVVJXVVZGRVJFUjBRbU5JUW5OYVUwSllZak5LYzFwSVpIQmFSMVZuVWtkV01scFhlSFpqUjFaNVNVWktiR0pIUmpCaFZ6bDFZM2xDUkZwWVNqQmhWMXB3V1RKR01HRlhPWFZKUlVZeFpFZG9kbU50YkRCbFZFVk1UVUZyUjBFeFZVVkRkM2REVW5wWmVFVjZRVkpDWjA1V1FrRnZUVU5yUm5kalIzaHNTVVZzZFZsNU5IaERla0ZLUW1kT1ZrSkJXVlJCYkZaVVRVaFpkMFZCV1VoTGIxcEplbW93UTBGUldVWkxORVZGUVVOSlJGbG5RVVZpYzFGTFF6azBVSEpzVjIxYVdHNVlaM1I0ZW1SV1NrdzRWREJUUjFsdVowUlNSM0J1WjI0elRqWlFWRGhLVFVWaU4wWkVhVFJpUW0xUWFFTnVXak12YzNFMlVFWXZZMGRqUzFoWGMwdzFkazkwWlZKb2VVbzBOWGd6UVZOUU4yTlBRaXRoWVc4NU1HWmpjSGhUZGk5RldrWmlibWxCWWs1bldrZG9TV2h3U1c4MFNEWk5TVWd6VFVKSlIwRXhWV1JGZDBWQ0wzZFJTVTFCV1VKQlpqaERRVkZCZDBoM1dVUldVakJxUWtKbmQwWnZRVlYxTjBSbGIxWm5lbWxLY1d0cGNHNWxkbkl6Y25JNWNreEtTM04zVW1kWlNVdDNXVUpDVVZWSVFWRkZSVTlxUVRSTlJGbEhRME56UjBGUlZVWkNla0ZDYUdsd2IyUklVbmRQYVRoMllqSk9lbU5ETldoalNFSnpXbE0xYW1JeU1IWmlNazU2WTBSQmVreFhSbmRqUjNoc1kyMDVkbVJIVG1oYWVrMTNUbmRaUkZaU01HWkNSRUYzVEdwQmMyOURjV2RMU1ZsdFlVaFNNR05FYjNaTU1rNTVZa00xYUdOSVFuTmFVelZxWWpJd2RsbFlRbmRpUjFaNVlqSTVNRmt5Um01TmVUVnFZMjEzZDBoUldVUldVakJQUWtKWlJVWkVPSFpzUTA1U01ERkVTbTFwWnprM1lrSTROV01yYkd0SFMxcE5RVFJIUVRGVlpFUjNSVUl2ZDFGRlFYZEpRa0pxUVZGQ1oyOXhhR3RwUnpreVRtdENaMGxDUWtGSlJrRkVRVXRDWjJkeGFHdHFUMUJSVVVSQmQwNXZRVVJDYkVGcVFrRllhRk54TlVsNVMyOW5UVU5RZEhjME9UQkNZVUkyTnpkRFlVVkhTbGgxWmxGQ0wwVnhXa2RrTmtOVGFtbERkRTl1ZFUxVVlsaFdXRzE0ZUdONFptdERUVkZFVkZOUWVHRnlXbGgyVG5KcmVGVXpWR3RWVFVrek0zbDZka1pXVmxKVU5IZDRWMHBET1RrMFQzTmtZMW8wSzFKSFRuTlpSSGxTTldkdFpISXdia1JIWnowaUxDSk5TVWxEVVhwRFEwRmpiV2RCZDBsQ1FXZEpTVXhqV0RocFRreEdVelZWZDBObldVbExiMXBKZW1vd1JVRjNUWGRhZWtWaVRVSnJSMEV4VlVWQmQzZFRVVmhDZDJKSFZXZFZiVGwyWkVOQ1JGRlRRWFJKUldONlRWTlpkMHBCV1VSV1VWRk1SRUl4UW1OSVFuTmFVMEpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJWUk5Ra1ZIUVRGVlJVTm5kMHRSV0VKM1lrZFZaMU5YTldwTWFrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmQwaG9ZMDVOVkZGM1RrUk5kMDFVWjNoUFZFRXlWMmhqVGsxNmEzZE9SRTEzVFZSbmVFOVVRVEpYYWtKdVRWSnpkMGRSV1VSV1VWRkVSRUpLUW1OSVFuTmFVMEpUWWpJNU1FbEZUa0pKUXpCblVucE5lRXBxUVd0Q1owNVdRa0Z6VFVoVlJuZGpSM2hzU1VWT2JHTnVVbkJhYld4cVdWaFNjR0l5TkdkUldGWXdZVWM1ZVdGWVVqVk5VazEzUlZGWlJGWlJVVXRFUVhCQ1kwaENjMXBUUWtwaWJVMTFUVkZ6ZDBOUldVUldVVkZIUlhkS1ZsVjZRakpOUWtGSFFubHhSMU5OTkRsQlowVkhRbE4xUWtKQlFXbEJNa2xCUWtwcWNFeDZNVUZqY1ZSMGEzbEtlV2RTVFdNelVrTldPR05YYWxSdVNHTkdRbUphUkhWWGJVSlRjRE5hU0hSbVZHcHFWSFY0ZUVWMFdDOHhTRGRaZVZsc00wbzJXVkppVkhwQ1VFVldiMEV2Vm1oWlJFdFlNVVI1ZUU1Q01HTlVaR1J4V0d3MVpIWk5WbnAwU3pVeE4wbEVkbGwxVmxSYVdIQnRhMDlzUlV0TllVNURUVVZCZDBoUldVUldVakJQUWtKWlJVWk1kWGN6Y1VaWlRUUnBZWEJKY1ZvemNqWTVOall2WVhsNVUzSk5RVGhIUVRGVlpFVjNSVUl2ZDFGR1RVRk5Ra0ZtT0hkRVoxbEVWbEl3VUVGUlNDOUNRVkZFUVdkRlIwMUJiMGREUTNGSFUwMDBPVUpCVFVSQk1tZEJUVWRWUTAxUlEwUTJZMGhGUm13MFlWaFVVVmt5WlROMk9VZDNUMEZGV2t4MVRpdDVVbWhJUmtRdk0yMWxiM2xvY0cxMlQzZG5VRlZ1VUZkVWVHNVROR0YwSzNGSmVGVkRUVWN4Yldsb1JFc3hRVE5WVkRneVRsRjZOakJwYlU5c1RUSTNhbUprYjFoME1sRm1lVVpOYlN0WmFHbGtSR3RNUmpGMlRGVmhaMDAyUW1kRU5UWkxlVXRCUFQwaVhYMC5leUowY21GdWMyRmpkR2x2Ymtsa0lqb2lNakF3TURBd01UQXlOVFk0TmpNeE15SXNJbTl5YVdkcGJtRnNWSEpoYm5OaFkzUnBiMjVKWkNJNklqSXdNREF3TURFd01qUTVPVE15T1RraUxDSjNaV0pQY21SbGNreHBibVZKZEdWdFNXUWlPaUl5TURBd01EQXdNVEV6T0RRME56QTJJaXdpWW5WdVpHeGxTV1FpT2lKamIyMHViRzlyYVMxd2NtOXFaV04wTG14dmEya3RiV1Z6YzJWdVoyVnlJaXdpY0hKdlpIVmpkRWxrSWpvaVkyOXRMbWRsZEhObGMzTnBiMjR1YjNKbkxuQnliMTl6ZFdJaUxDSnpkV0p6WTNKcGNIUnBiMjVIY205MWNFbGtaVzUwYVdacFpYSWlPaUl5TVRjMU1qZ3hOQ0lzSW5CMWNtTm9ZWE5sUkdGMFpTSTZNVGMxT1RNNE9EYzJOekF3TUN3aWIzSnBaMmx1WVd4UWRYSmphR0Z6WlVSaGRHVWlPakUzTlRrek1ERTRNek13TURBc0ltVjRjR2x5WlhORVlYUmxJam94TnpVNU16ZzRPVFEzTURBd0xDSnhkV0Z1ZEdsMGVTSTZNU3dpZEhsd1pTSTZJa0YxZEc4dFVtVnVaWGRoWW14bElGTjFZbk5qY21sd2RHbHZiaUlzSW1sdVFYQndUM2R1WlhKemFHbHdWSGx3WlNJNklsQlZVa05JUVZORlJDSXNJbk5wWjI1bFpFUmhkR1VpT2pFM05Ua3pPRGt3TkRFMk1EUXNJbVZ1ZG1seWIyNXRaVzUwSWpvaVUyRnVaR0p2ZUNJc0luUnlZVzV6WVdOMGFXOXVVbVZoYzI5dUlqb2lVRlZTUTBoQlUwVWlMQ0p6ZEc5eVpXWnliMjUwSWpvaVFWVlRJaXdpYzNSdmNtVm1jbTl1ZEVsa0lqb2lNVFF6TkRZd0lpd2ljSEpwWTJVaU9qRTVPVEFzSW1OMWNuSmxibU41SWpvaVFWVkVJaXdpWVhCd1ZISmhibk5oWTNScGIyNUpaQ0k2SWpjd05EZzVOelEyT1Rrd016TTRNemt4T1NKOS5oNkVLNzYtV2dZSU9ucHBvRDV6Sk5jMGd5Mkl0TXp2MjBWYi1kalhjdzM0d01GR2QwX3U2Nk00VG5sa1BfRnJKXzIwZW5OMnJuUkZGQWhXV1piWklBZyIsInNpZ25lZFJlbmV3YWxJbmZvIjoiZXlKaGJHY2lPaUpGVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxGVFZSRFEwRTNZV2RCZDBsQ1FXZEpVVkk0UzBoNlpHNDFOVFJhTDFWdmNtRmtUbmc1ZEhwQlMwSm5aM0ZvYTJwUFVGRlJSRUY2UWpGTlZWRjNVV2RaUkZaUlVVUkVSSFJDWTBoQ2MxcFRRbGhpTTBweldraGtjRnBIVldkU1IxWXlXbGQ0ZG1OSFZubEpSa3BzWWtkR01HRlhPWFZqZVVKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVXhOUVd0SFFURlZSVU4zZDBOU2VsbDRSWHBCVWtKblRsWkNRVzlOUTJ0R2QyTkhlR3hKUld4MVdYazBlRU42UVVwQ1owNVdRa0ZaVkVGc1ZsUk5RalJZUkZSSk1VMUVhM2hQVkVVMVRrUlJNVTFXYjFoRVZFa3pUVlJCZUUxNlJUTk9SR041VFRGdmQyZGFTWGhSUkVFclFtZE9Wa0pCVFUxT01VSjVZakpSWjFKVlRrUkpSVEZvV1hsQ1FtTklRV2RWTTFKMlkyMVZaMWxYTld0SlIyeFZaRmMxYkdONVFsUmtSemw1V2xOQ1UxcFhUbXhoV0VJd1NVWk9jRm95TlhCaWJXTjRURVJCY1VKblRsWkNRWE5OU1RCR2QyTkhlR3hKUm1SMlkyMTRhMlF5Ykd0YVUwSkZXbGhhYkdKSE9YZGFXRWxuVlcxV2MxbFlVbkJpTWpWNlRWSk5kMFZSV1VSV1VWRkxSRUZ3UW1OSVFuTmFVMEpLWW0xTmRVMVJjM2REVVZsRVZsRlJSMFYzU2xaVmVrSmFUVUpOUjBKNWNVZFRUVFE1UVdkRlIwTkRjVWRUVFRRNVFYZEZTRUV3U1VGQ1RtNVdkbWhqZGpkcFZDczNSWGcxZEVKTlFtZHlVWE53U0hwSmMxaFNhVEJaZUdabGF6ZHNkamgzUlcxcUwySklhVmQwVG5kS2NXTXlRbTlJZW5OUmFVVnFVRGRMUmtsSlMyYzBXVGg1TUM5dWVXNTFRVzFxWjJkSlNVMUpTVU5DUkVGTlFtZE9Wa2hTVFVKQlpqaEZRV3BCUVUxQ09FZEJNVlZrU1hkUldVMUNZVUZHUkRoMmJFTk9VakF4UkVwdGFXYzVOMkpDT0RWaksyeHJSMHRhVFVoQlIwTkRjMGRCVVZWR1FuZEZRa0pIVVhkWmFrRjBRbWRuY2tKblJVWkNVV04zUVc5WmFHRklVakJqUkc5MlRESk9iR051VW5wTWJVWjNZMGQ0YkV4dFRuWmlVemt6WkRKU2VWcDZXWFZhUjFaNVRVUkZSME5EYzBkQlVWVkdRbnBCUW1ocFZtOWtTRkozVDJrNGRtSXlUbnBqUXpWb1kwaENjMXBUTldwaU1qQjJZakpPZW1ORVFYcE1XR1F6V2toS2JrNXFRWGxOU1VsQ1NHZFpSRlpTTUdkQ1NVbENSbFJEUTBGU1JYZG5aMFZPUW1kdmNXaHJhVWM1TWs1clFsRlpRazFKU0N0TlNVaEVRbWRuY2tKblJVWkNVV05EUVdwRFFuUm5lVUp6TVVwc1lrZHNhR0p0VG14SlJ6bDFTVWhTYjJGWVRXZFpNbFo1WkVkc2JXRlhUbWhrUjFWbldXNXJaMWxYTlRWSlNFSm9ZMjVTTlVsSFJucGpNMVowV2xoTloxbFhUbXBhV0VJd1dWYzFhbHBUUW5aYWFVSXdZVWRWWjJSSGFHeGlhVUpvWTBoQ2MyRlhUbWhaYlhoc1NVaE9NRmxYTld0WldFcHJTVWhTYkdOdE1YcEpSMFoxV2tOQ2FtSXlOV3RoV0ZKd1lqSTFla2xIT1cxSlNGWjZXbE4zWjFreVZubGtSMnh0WVZkT2FHUkhWV2RqUnpsellWZE9OVWxIUm5WYVEwSnFXbGhLTUdGWFduQlpNa1l3WVZjNWRVbElRbmxaVjA0d1lWZE9iRWxJVGpCWldGSnNZbGRXZFdSSVRYVk5SRmxIUTBOelIwRlJWVVpDZDBsQ1JtbHdiMlJJVW5kUGFUaDJaRE5rTTB4dFJuZGpSM2hzVEcxT2RtSlRPV3BhV0Vvd1lWZGFjRmt5UmpCYVYwWXhaRWRvZG1OdGJEQmxVemgzU0ZGWlJGWlNNRTlDUWxsRlJrbEdhVzlITkhkTlRWWkJNV3QxT1hwS2JVZE9VRUZXYmpObGNVMUJORWRCTVZWa1JIZEZRaTkzVVVWQmQwbElaMFJCVVVKbmIzRm9hMmxIT1RKT2EwSm5jMEpDUVVsR1FVUkJTMEpuWjNGb2EycFBVRkZSUkVGM1RuQkJSRUp0UVdwRlFTdHhXRzVTUlVNM2FGaEpWMVpNYzB4NGVtNXFVbkJKZWxCbU4xWkllamxXTDBOVWJUZ3JURXBzY2xGbGNHNXRZMUIyUjB4T1kxZzJXRkJ1YkdOblRFRkJha1ZCTlVscVRscExaMmMxY0ZFM09XdHVSalJKWWxSWVpFdDJPSFoxZEVsRVRWaEViV3BRVmxRelpFZDJSblJ6UjFKM1dFOTVkMUl5YTFwRFpGTnlabVZ2ZENJc0lrMUpTVVJHYWtORFFYQjVaMEYzU1VKQlowbFZTWE5IYUZKM2NEQmpNbTUyVlRSWlUzbGpZV1pRVkdwNllrNWpkME5uV1VsTGIxcEplbW93UlVGM1RYZGFla1ZpVFVKclIwRXhWVVZCZDNkVFVWaENkMkpIVldkVmJUbDJaRU5DUkZGVFFYUkpSV042VFZOWmQwcEJXVVJXVVZGTVJFSXhRbU5JUW5OYVUwSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlZSTlFrVkhRVEZWUlVObmQwdFJXRUozWWtkVloxTlhOV3BNYWtWTVRVRnJSMEV4VlVWQ2FFMURWbFpOZDBob1kwNU5ha1YzVFhwRk0wMXFRWHBPZWtWM1YyaGpUazE2V1hkTmVrVTFUVVJCZDAxRVFYZFhha0l4VFZWUmQxRm5XVVJXVVZGRVJFUjBRbU5JUW5OYVUwSllZak5LYzFwSVpIQmFSMVZuVWtkV01scFhlSFpqUjFaNVNVWktiR0pIUmpCaFZ6bDFZM2xDUkZwWVNqQmhWMXB3V1RKR01HRlhPWFZKUlVZeFpFZG9kbU50YkRCbFZFVk1UVUZyUjBFeFZVVkRkM2REVW5wWmVFVjZRVkpDWjA1V1FrRnZUVU5yUm5kalIzaHNTVVZzZFZsNU5IaERla0ZLUW1kT1ZrSkJXVlJCYkZaVVRVaFpkMFZCV1VoTGIxcEplbW93UTBGUldVWkxORVZGUVVOSlJGbG5RVVZpYzFGTFF6azBVSEpzVjIxYVdHNVlaM1I0ZW1SV1NrdzRWREJUUjFsdVowUlNSM0J1WjI0elRqWlFWRGhLVFVWaU4wWkVhVFJpUW0xUWFFTnVXak12YzNFMlVFWXZZMGRqUzFoWGMwdzFkazkwWlZKb2VVbzBOWGd6UVZOUU4yTlBRaXRoWVc4NU1HWmpjSGhUZGk5RldrWmlibWxCWWs1bldrZG9TV2h3U1c4MFNEWk5TVWd6VFVKSlIwRXhWV1JGZDBWQ0wzZFJTVTFCV1VKQlpqaERRVkZCZDBoM1dVUldVakJxUWtKbmQwWnZRVlYxTjBSbGIxWm5lbWxLY1d0cGNHNWxkbkl6Y25JNWNreEtTM04zVW1kWlNVdDNXVUpDVVZWSVFWRkZSVTlxUVRSTlJGbEhRME56UjBGUlZVWkNla0ZDYUdsd2IyUklVbmRQYVRoMllqSk9lbU5ETldoalNFSnpXbE0xYW1JeU1IWmlNazU2WTBSQmVreFhSbmRqUjNoc1kyMDVkbVJIVG1oYWVrMTNUbmRaUkZaU01HWkNSRUYzVEdwQmMyOURjV2RMU1ZsdFlVaFNNR05FYjNaTU1rNTVZa00xYUdOSVFuTmFVelZxWWpJd2RsbFlRbmRpUjFaNVlqSTVNRmt5Um01TmVUVnFZMjEzZDBoUldVUldVakJQUWtKWlJVWkVPSFpzUTA1U01ERkVTbTFwWnprM1lrSTROV01yYkd0SFMxcE5RVFJIUVRGVlpFUjNSVUl2ZDFGRlFYZEpRa0pxUVZGQ1oyOXhhR3RwUnpreVRtdENaMGxDUWtGSlJrRkVRVXRDWjJkeGFHdHFUMUJSVVVSQmQwNXZRVVJDYkVGcVFrRllhRk54TlVsNVMyOW5UVU5RZEhjME9UQkNZVUkyTnpkRFlVVkhTbGgxWmxGQ0wwVnhXa2RrTmtOVGFtbERkRTl1ZFUxVVlsaFdXRzE0ZUdONFptdERUVkZFVkZOUWVHRnlXbGgyVG5KcmVGVXpWR3RWVFVrek0zbDZka1pXVmxKVU5IZDRWMHBET1RrMFQzTmtZMW8wSzFKSFRuTlpSSGxTTldkdFpISXdia1JIWnowaUxDSk5TVWxEVVhwRFEwRmpiV2RCZDBsQ1FXZEpTVXhqV0RocFRreEdVelZWZDBObldVbExiMXBKZW1vd1JVRjNUWGRhZWtWaVRVSnJSMEV4VlVWQmQzZFRVVmhDZDJKSFZXZFZiVGwyWkVOQ1JGRlRRWFJKUldONlRWTlpkMHBCV1VSV1VWRk1SRUl4UW1OSVFuTmFVMEpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJWUk5Ra1ZIUVRGVlJVTm5kMHRSV0VKM1lrZFZaMU5YTldwTWFrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmQwaG9ZMDVOVkZGM1RrUk5kMDFVWjNoUFZFRXlWMmhqVGsxNmEzZE9SRTEzVFZSbmVFOVVRVEpYYWtKdVRWSnpkMGRSV1VSV1VWRkVSRUpLUW1OSVFuTmFVMEpUWWpJNU1FbEZUa0pKUXpCblVucE5lRXBxUVd0Q1owNVdRa0Z6VFVoVlJuZGpSM2hzU1VWT2JHTnVVbkJhYld4cVdWaFNjR0l5TkdkUldGWXdZVWM1ZVdGWVVqVk5VazEzUlZGWlJGWlJVVXRFUVhCQ1kwaENjMXBUUWtwaWJVMTFUVkZ6ZDBOUldVUldVVkZIUlhkS1ZsVjZRakpOUWtGSFFubHhSMU5OTkRsQlowVkhRbE4xUWtKQlFXbEJNa2xCUWtwcWNFeDZNVUZqY1ZSMGEzbEtlV2RTVFdNelVrTldPR05YYWxSdVNHTkdRbUphUkhWWGJVSlRjRE5hU0hSbVZHcHFWSFY0ZUVWMFdDOHhTRGRaZVZsc00wbzJXVkppVkhwQ1VFVldiMEV2Vm1oWlJFdFlNVVI1ZUU1Q01HTlVaR1J4V0d3MVpIWk5WbnAwU3pVeE4wbEVkbGwxVmxSYVdIQnRhMDlzUlV0TllVNURUVVZCZDBoUldVUldVakJQUWtKWlJVWk1kWGN6Y1VaWlRUUnBZWEJKY1ZvemNqWTVOall2WVhsNVUzSk5RVGhIUVRGVlpFVjNSVUl2ZDFGR1RVRk5Ra0ZtT0hkRVoxbEVWbEl3VUVGUlNDOUNRVkZFUVdkRlIwMUJiMGREUTNGSFUwMDBPVUpCVFVSQk1tZEJUVWRWUTAxUlEwUTJZMGhGUm13MFlWaFVVVmt5WlROMk9VZDNUMEZGV2t4MVRpdDVVbWhJUmtRdk0yMWxiM2xvY0cxMlQzZG5VRlZ1VUZkVWVHNVROR0YwSzNGSmVGVkRUVWN4Yldsb1JFc3hRVE5WVkRneVRsRjZOakJwYlU5c1RUSTNhbUprYjFoME1sRm1lVVpOYlN0WmFHbGtSR3RNUmpGMlRGVmhaMDAyUW1kRU5UWkxlVXRCUFQwaVhYMC5leUpsZUhCcGNtRjBhVzl1U1c1MFpXNTBJam94TENKdmNtbG5hVzVoYkZSeVlXNXpZV04wYVc5dVNXUWlPaUl5TURBd01EQXhNREkwT1Rrek1qazVJaXdpWVhWMGIxSmxibVYzVUhKdlpIVmpkRWxrSWpvaVkyOXRMbWRsZEhObGMzTnBiMjR1YjNKbkxuQnliMTl6ZFdJaUxDSndjbTlrZFdOMFNXUWlPaUpqYjIwdVoyVjBjMlZ6YzJsdmJpNXZjbWN1Y0hKdlgzTjFZaUlzSW1GMWRHOVNaVzVsZDFOMFlYUjFjeUk2TUN3aWFYTkpia0pwYkd4cGJtZFNaWFJ5ZVZCbGNtbHZaQ0k2Wm1Gc2MyVXNJbk5wWjI1bFpFUmhkR1VpT2pFM05Ua3pPRGt3TkRFMk1EUXNJbVZ1ZG1seWIyNXRaVzUwSWpvaVUyRnVaR0p2ZUNJc0luSmxZMlZ1ZEZOMVluTmpjbWx3ZEdsdmJsTjBZWEowUkdGMFpTSTZNVGMxT1RNNE9EYzJOekF3TUN3aWNtVnVaWGRoYkVSaGRHVWlPakUzTlRrek9EZzVORGN3TURBc0ltRndjRlJ5WVc1ellXTjBhVzl1U1dRaU9pSTNNRFE0T1RjME5qazVNRE16T0RNNU1Ua2lmUS53VGpZaG9pQl9yZURBSWFGWEpzME1vTVhsWHFMQWtfUXNpUzMtbzA4VWVWaWhWaElVZlFEX2NZdm9vaDlNSGZVRTduNnFGLU5kdURBNUpYamlqNmRLdyIsInN0YXR1cyI6Mn0sInZlcnNpb24iOiIyLjAiLCJzaWduZWREYXRlIjoxNzU5Mzg5MDQxNjA0fQ.LdBD3eODhNJ42LPe4D7DBRmiRw8MLuWRlOZLeHeFqyQX4P57rHGgb_kVaxhcnmPmgKuIevrujqmPNCpK9rdzKQ"
                }
                ''')

                signed_payload: str = typing.cast(str, notification_payload_json['signedPayload'])
                body: AppleResponseBodyV2DecodedPayload = core.signed_data_verifier.verify_and_decode_notification(signed_payload)
                dump_apple_signed_payloads(core, body)

            # NOTE: Generated by dump_apple_signed_payloads
            # NOTE: Signed Payload
            body                                     = AppleResponseBodyV2DecodedPayload()
            body_data                                = AppleData()
            body_data.appAppleId                     = 1470168868
            body_data.bundleId                       = 'com.loki-project.loki-messenger'
            body_data.bundleVersion                  = '637'
            body_data.consumptionRequestReason       = None
            body_data.environment                    = AppleEnvironment.SANDBOX
            body_data.rawConsumptionRequestReason    = None
            body_data.rawEnvironment                 = 'Sandbox'
            body_data.rawStatus                      = 2
            body_data.signedRenewalInfo              = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJleHBpcmF0aW9uSW50ZW50IjoxLCJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MCwiaXNJbkJpbGxpbmdSZXRyeVBlcmlvZCI6ZmFsc2UsInNpZ25lZERhdGUiOjE3NTkzODkwNDE2MDQsImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc1OTM4ODc2NzAwMCwicmVuZXdhbERhdGUiOjE3NTkzODg5NDcwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.wTjYhoiB_reDAIaFXJs0MoMXlXqLAk_QsiS3-o08UeVihVhIUfQD_cYvooh9MHfUE7n6qF-NduDA5JXjij6dKw'
            body_data.signedTransactionInfo          = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNTY4NjMxMyIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTEzODQ0NzA2IiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTM4ODc2NzAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5Mzg4OTQ3MDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTkzODkwNDE2MDQsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.h6EK76-WgYIOnppoD5zJNc0gy2ItMzv20Vb-djXcw34wMFGd0_u66M4TnlkP_FrJ_20enN2rnRFFAhWWZbZIAg'
            body_data.status                         = AppleStatus.EXPIRED
            body.data                                = body_data
            body.externalPurchaseToken               = None
            body.notificationType                    = AppleNotificationTypeV2.EXPIRED
            body.notificationUUID                    = 'c7726298-32eb-48f7-9623-097ff6de4d69'
            body.rawNotificationType                 = 'EXPIRED'
            body.rawSubtype                          = 'VOLUNTARY'
            body.signedDate                          = 1759389041604
            body.subtype                             = AppleSubtype.VOLUNTARY
            body.summary                             = None
            body.version                             = '2.0'

            # NOTE: Signed Renewal Info
            renewal_info                             = AppleJWSRenewalInfoDecodedPayload()
            renewal_info.appAccountToken             = None
            renewal_info.appTransactionId            = '704897469903383919'
            renewal_info.autoRenewProductId          = None
            renewal_info.autoRenewStatus             = None
            renewal_info.currency                    = 'AUD'
            renewal_info.eligibleWinBackOfferIds     = None
            renewal_info.environment                 = AppleEnvironment.SANDBOX
            renewal_info.expirationIntent            = None
            renewal_info.gracePeriodExpiresDate      = None
            renewal_info.isInBillingRetryPeriod      = None
            renewal_info.offerDiscountType           = None
            renewal_info.offerIdentifier             = None
            renewal_info.offerPeriod                 = None
            renewal_info.offerType                   = None
            renewal_info.originalTransactionId       = '2000001024993299'
            renewal_info.priceIncreaseStatus         = None
            renewal_info.productId                   = 'com.getsession.org.pro_sub'
            renewal_info.rawAutoRenewStatus          = None
            renewal_info.rawEnvironment              = 'Sandbox'
            renewal_info.rawExpirationIntent         = None
            renewal_info.rawOfferDiscountType        = None
            renewal_info.rawOfferType                = None
            renewal_info.rawPriceIncreaseStatus      = None
            renewal_info.recentSubscriptionStartDate = None
            renewal_info.renewalDate                 = None
            renewal_info.renewalPrice                = None
            renewal_info.signedDate                  = 1759389041604

            # NOTE: Signed Transaction Info
            tx_info                                  = AppleJWSTransactionDecodedPayload()
            tx_info.appAccountToken                  = None
            tx_info.appTransactionId                 = '704897469903383919'
            tx_info.bundleId                         = 'com.loki-project.loki-messenger'
            tx_info.currency                         = 'AUD'
            tx_info.environment                      = AppleEnvironment.SANDBOX
            tx_info.expiresDate                      = 1759388947000
            tx_info.inAppOwnershipType               = AppleInAppOwnershipType.PURCHASED
            tx_info.isUpgraded                       = None
            tx_info.offerDiscountType                = None
            tx_info.offerIdentifier                  = None
            tx_info.offerPeriod                      = None
            tx_info.offerType                        = None
            tx_info.originalPurchaseDate             = 1759301833000
            tx_info.originalTransactionId            = '2000001024993299'
            tx_info.price                            = 1990
            tx_info.productId                        = 'com.getsession.org.pro_sub'
            tx_info.purchaseDate                     = 1759388767000
            tx_info.quantity                         = 1
            tx_info.rawEnvironment                   = 'Sandbox'
            tx_info.rawInAppOwnershipType            = 'PURCHASED'
            tx_info.rawOfferDiscountType             = None
            tx_info.rawOfferType                     = None
            tx_info.rawRevocationReason              = None
            tx_info.rawTransactionReason             = 'PURCHASE'
            tx_info.rawType                          = 'Auto-Renewable Subscription'
            tx_info.revocationDate                   = None
            tx_info.revocationReason                 = None
            tx_info.signedDate                       = 1759389041604
            tx_info.storefront                       = 'AUS'
            tx_info.storefrontId                     = '143460'
            tx_info.subscriptionGroupIdentifier      = '21752814'
            tx_info.transactionId                    = '2000001025686313'
            tx_info.transactionReason                = AppleTransactionReason.PURCHASE
            tx_info.type                             = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
            tx_info.webOrderLineItemId               = '2000000113844706'

            decoded_notification = platform_apple.DecodedNotification(body=body, tx_info=tx_info, renewal_info=renewal_info)

            err = base.ErrorSink()
            platform_apple.handle_notification(decoded_notification=decoded_notification, sql_conn=test.sql_conn, err=err)
            assert not err.has(), err.msg_list

            # NOTE: The payment expires as per Apple's notification. We don't have to do anything
            # necessarily as our proofs will self-expire.

            # NOTE: Check payment is still in the DB
            payment_list: list[backend.PaymentRow]                    = backend.get_payments_list(test.sql_conn)
            assert len(payment_list)                                 == 1
            assert payment_list[0].master_pkey                       == None
            assert payment_list[0].status                            == base.PaymentStatus.Unredeemed
            assert payment_list[0].plan                              == base.ProPlan.OneMonth
            assert payment_list[0].payment_provider                  == base.PaymentProvider.iOSAppStore
            assert payment_list[0].unredeemed_unix_ts_ms             == tx_info.purchaseDate
            assert payment_list[0].redeemed_unix_ts_ms               == None
            assert payment_list[0].expiry_unix_ts_ms                 == tx_info.expiresDate
            assert payment_list[0].grace_period_duration_ms          == platform_apple.GRACE_PERIOD_DURATION_MS
            assert payment_list[0].platform_refund_expiry_unix_ts_ms == 0
            assert payment_list[0].revoked_unix_ts_ms                == None
            assert payment_list[0].apple.original_tx_id              == tx_info.originalTransactionId
            assert payment_list[0].apple.tx_id                       == tx_info.transactionId
            assert payment_list[0].apple.web_line_order_tx_id        == tx_info.webOrderLineItemId

            # NOTE: Now expire the payment
            _ = backend.expire_payments_revocations_and_users(sql_conn=test.sql_conn, unix_ts_ms=payment_list[0].expiry_unix_ts_ms + 1)

            # NOTE: Now check that the payments were marked expired
            payment_list: list[backend.PaymentRow] = backend.get_payments_list(test.sql_conn)
            assert len(payment_list) == 1
            assert payment_list[0].master_pkey                       == None
            assert payment_list[0].status                            == base.PaymentStatus.Expired
            assert payment_list[0].plan                              == base.ProPlan.OneMonth
            assert payment_list[0].payment_provider                  == base.PaymentProvider.iOSAppStore
            assert payment_list[0].unredeemed_unix_ts_ms             == tx_info.purchaseDate
            assert payment_list[0].redeemed_unix_ts_ms               == None
            assert payment_list[0].expiry_unix_ts_ms                 == tx_info.expiresDate
            assert payment_list[0].grace_period_duration_ms          == platform_apple.GRACE_PERIOD_DURATION_MS
            assert payment_list[0].platform_refund_expiry_unix_ts_ms == 0
            assert payment_list[0].revoked_unix_ts_ms                == None
            assert payment_list[0].apple.original_tx_id              == tx_info.originalTransactionId
            assert payment_list[0].apple.tx_id                       == tx_info.transactionId
            assert payment_list[0].apple.web_line_order_tx_id        == tx_info.webOrderLineItemId


    # NOTE: Execute the sequence
    #  - 0 [SUBSCRIBED,                sub: RESUBSCRIBE]         Subscribe to 3 months
    #  - 1 [DID_CHANGE_RENEWAL_PREF,   sub: UPGRADE]             "Upgrade" to 1 wk (happens immediately)
    #  - 2 [DID_CHANGE_RENEWAL_STATUS, sub: AUTO_RENEW_DISABLED] Disable auto-renew
    #  - 3 [DID_CHANGE_RENEWAL_PREF,   sub: DOWNGRADE]           Queue downgrade to 3 months at end of 1wk billing cycle
    #  - 4 [DID_CHANGE_RENEWAL_PREF]                             Cancel the downgrade (we are now back at 1wk subscription)
    #  - 5 [DID_CHANGE_RENEWAL_STATUS, sub: AUTO_RENEW_DISABLED] Disable auto-renew
    #  - 6 [EXPIRED,                   sub: VOLUNTARY]           ??
    with TestingContext(db_path='file:test_platform_apple_db?mode=memory&cache=shared', uri=True) as test:
        # NOTE: Original payload (this requires keys to decrypt)
        if 0:
            e00_sub_to_3_months: dict[str, base.JSONValue] = json.loads('''
            {
            "signedPayload": "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJub3RpZmljYXRpb25UeXBlIjoiU1VCU0NSSUJFRCIsInN1YnR5cGUiOiJSRVNVQlNDUklCRSIsIm5vdGlmaWNhdGlvblVVSUQiOiJmZWU2YWRlNi01ODcxLTRlMGYtOWQyZS01ZDYyMjlhMjQwMjciLCJkYXRhIjp7ImFwcEFwcGxlSWQiOjE0NzAxNjg4NjgsImJ1bmRsZUlkIjoiY29tLmxva2ktcHJvamVjdC5sb2tpLW1lc3NlbmdlciIsImJ1bmRsZVZlcnNpb24iOiI2MzciLCJlbnZpcm9ubWVudCI6IlNhbmRib3giLCJzaWduZWRUcmFuc2FjdGlvbkluZm8iOiJleUpoYkdjaU9pSkZVekkxTmlJc0luZzFZeUk2V3lKTlNVbEZUVlJEUTBFM1lXZEJkMGxDUVdkSlVWSTRTMGg2Wkc0MU5UUmFMMVZ2Y21Ga1RuZzVkSHBCUzBKblozRm9hMnBQVUZGUlJFRjZRakZOVlZGM1VXZFpSRlpSVVVSRVJIUkNZMGhDYzFwVFFsaGlNMHB6V2toa2NGcEhWV2RTUjFZeVdsZDRkbU5IVm5sSlJrcHNZa2RHTUdGWE9YVmplVUpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJVeE5RV3RIUVRGVlJVTjNkME5TZWxsNFJYcEJVa0puVGxaQ1FXOU5RMnRHZDJOSGVHeEpSV3gxV1hrMGVFTjZRVXBDWjA1V1FrRlpWRUZzVmxSTlFqUllSRlJKTVUxRWEzaFBWRVUxVGtSUk1VMVdiMWhFVkVrelRWUkJlRTE2UlROT1JHTjVUVEZ2ZDJkYVNYaFJSRUVyUW1kT1ZrSkJUVTFPTVVKNVlqSlJaMUpWVGtSSlJURm9XWGxDUW1OSVFXZFZNMUoyWTIxVloxbFhOV3RKUjJ4VlpGYzFiR041UWxSa1J6bDVXbE5DVTFwWFRteGhXRUl3U1VaT2NGb3lOWEJpYldONFRFUkJjVUpuVGxaQ1FYTk5TVEJHZDJOSGVHeEpSbVIyWTIxNGEyUXliR3RhVTBKRldsaGFiR0pIT1hkYVdFbG5WVzFXYzFsWVVuQmlNalY2VFZKTmQwVlJXVVJXVVZGTFJFRndRbU5JUW5OYVUwSktZbTFOZFUxUmMzZERVVmxFVmxGUlIwVjNTbFpWZWtKYVRVSk5SMEo1Y1VkVFRUUTVRV2RGUjBORGNVZFRUVFE1UVhkRlNFRXdTVUZDVG01V2RtaGpkamRwVkNzM1JYZzFkRUpOUW1keVVYTndTSHBKYzFoU2FUQlplR1psYXpkc2RqaDNSVzFxTDJKSWFWZDBUbmRLY1dNeVFtOUllbk5SYVVWcVVEZExSa2xKUzJjMFdUaDVNQzl1ZVc1MVFXMXFaMmRKU1UxSlNVTkNSRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDT0VkQk1WVmtTWGRSV1UxQ1lVRkdSRGgyYkVOT1VqQXhSRXB0YVdjNU4ySkNPRFZqSzJ4clIwdGFUVWhCUjBORGMwZEJVVlZHUW5kRlFrSkhVWGRaYWtGMFFtZG5ja0puUlVaQ1VXTjNRVzlaYUdGSVVqQmpSRzkyVERKT2JHTnVVbnBNYlVaM1kwZDRiRXh0VG5aaVV6a3paREpTZVZwNldYVmFSMVo1VFVSRlIwTkRjMGRCVVZWR1FucEJRbWhwVm05a1NGSjNUMms0ZG1JeVRucGpRelZvWTBoQ2MxcFROV3BpTWpCMllqSk9lbU5FUVhwTVdHUXpXa2hLYms1cVFYbE5TVWxDU0dkWlJGWlNNR2RDU1VsQ1JsUkRRMEZTUlhkblowVk9RbWR2Y1docmFVYzVNazVyUWxGWlFrMUpTQ3ROU1VoRVFtZG5ja0puUlVaQ1VXTkRRV3BEUW5SbmVVSnpNVXBzWWtkc2FHSnRUbXhKUnpsMVNVaFNiMkZZVFdkWk1sWjVaRWRzYldGWFRtaGtSMVZuV1c1cloxbFhOVFZKU0VKb1kyNVNOVWxIUm5wak0xWjBXbGhOWjFsWFRtcGFXRUl3V1ZjMWFscFRRblphYVVJd1lVZFZaMlJIYUd4aWFVSm9ZMGhDYzJGWFRtaFpiWGhzU1VoT01GbFhOV3RaV0VwclNVaFNiR050TVhwSlIwWjFXa05DYW1JeU5XdGhXRkp3WWpJMWVrbEhPVzFKU0ZaNldsTjNaMWt5Vm5sa1IyeHRZVmRPYUdSSFZXZGpSemx6WVZkT05VbEhSblZhUTBKcVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsSVFubFpWMDR3WVZkT2JFbElUakJaV0ZKc1lsZFdkV1JJVFhWTlJGbEhRME56UjBGUlZVWkNkMGxDUm1sd2IyUklVbmRQYVRoMlpETmtNMHh0Um5kalIzaHNURzFPZG1KVE9XcGFXRW93WVZkYWNGa3lSakJhVjBZeFpFZG9kbU50YkRCbFV6aDNTRkZaUkZaU01FOUNRbGxGUmtsR2FXOUhOSGROVFZaQk1XdDFPWHBLYlVkT1VFRldiak5sY1UxQk5FZEJNVlZrUkhkRlFpOTNVVVZCZDBsSVowUkJVVUpuYjNGb2EybEhPVEpPYTBKbmMwSkNRVWxHUVVSQlMwSm5aM0ZvYTJwUFVGRlJSRUYzVG5CQlJFSnRRV3BGUVN0eFdHNVNSVU0zYUZoSlYxWk1jMHg0ZW01cVVuQkplbEJtTjFaSWVqbFdMME5VYlRnclRFcHNjbEZsY0c1dFkxQjJSMHhPWTFnMldGQnViR05uVEVGQmFrVkJOVWxxVGxwTFoyYzFjRkUzT1d0dVJqUkpZbFJZWkV0Mk9IWjFkRWxFVFZoRWJXcFFWbFF6WkVkMlJuUnpSMUozV0U5NWQxSXlhMXBEWkZOeVptVnZkQ0lzSWsxSlNVUkdha05EUVhCNVowRjNTVUpCWjBsVlNYTkhhRkozY0RCak1tNTJWVFJaVTNsallXWlFWR3A2WWs1amQwTm5XVWxMYjFwSmVtb3dSVUYzVFhkYWVrVmlUVUpyUjBFeFZVVkJkM2RUVVZoQ2QySkhWV2RWYlRsMlpFTkNSRkZUUVhSSlJXTjZUVk5aZDBwQldVUldVVkZNUkVJeFFtTklRbk5hVTBKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVlJOUWtWSFFURlZSVU5uZDB0UldFSjNZa2RWWjFOWE5XcE1ha1ZNVFVGclIwRXhWVVZDYUUxRFZsWk5kMGhvWTA1TmFrVjNUWHBGTTAxcVFYcE9la1YzVjJoalRrMTZXWGROZWtVMVRVUkJkMDFFUVhkWGFrSXhUVlZSZDFGbldVUldVVkZFUkVSMFFtTklRbk5hVTBKWVlqTktjMXBJWkhCYVIxVm5Va2RXTWxwWGVIWmpSMVo1U1VaS2JHSkhSakJoVnpsMVkzbENSRnBZU2pCaFYxcHdXVEpHTUdGWE9YVkpSVVl4WkVkb2RtTnRiREJsVkVWTVRVRnJSMEV4VlVWRGQzZERVbnBaZUVWNlFWSkNaMDVXUWtGdlRVTnJSbmRqUjNoc1NVVnNkVmw1TkhoRGVrRktRbWRPVmtKQldWUkJiRlpVVFVoWmQwVkJXVWhMYjFwSmVtb3dRMEZSV1VaTE5FVkZRVU5KUkZsblFVVmljMUZMUXprMFVISnNWMjFhV0c1WVozUjRlbVJXU2t3NFZEQlRSMWx1WjBSU1IzQnVaMjR6VGpaUVZEaEtUVVZpTjBaRWFUUmlRbTFRYUVOdVdqTXZjM0UyVUVZdlkwZGpTMWhYYzB3MWRrOTBaVkpvZVVvME5YZ3pRVk5RTjJOUFFpdGhZVzg1TUdaamNIaFRkaTlGV2taaWJtbEJZazVuV2tkb1NXaHdTVzgwU0RaTlNVZ3pUVUpKUjBFeFZXUkZkMFZDTDNkUlNVMUJXVUpCWmpoRFFWRkJkMGgzV1VSV1VqQnFRa0puZDBadlFWVjFOMFJsYjFabmVtbEtjV3RwY0c1bGRuSXpjbkk1Y2t4S1MzTjNVbWRaU1V0M1dVSkNVVlZJUVZGRlJVOXFRVFJOUkZsSFEwTnpSMEZSVlVaQ2VrRkNhR2x3YjJSSVVuZFBhVGgyWWpKT2VtTkROV2hqU0VKeldsTTFhbUl5TUhaaU1rNTZZMFJCZWt4WFJuZGpSM2hzWTIwNWRtUkhUbWhhZWsxM1RuZFpSRlpTTUdaQ1JFRjNUR3BCYzI5RGNXZExTVmx0WVVoU01HTkViM1pNTWs1NVlrTTFhR05JUW5OYVV6VnFZakl3ZGxsWVFuZGlSMVo1WWpJNU1Ga3lSbTVOZVRWcVkyMTNkMGhSV1VSV1VqQlBRa0paUlVaRU9IWnNRMDVTTURGRVNtMXBaemszWWtJNE5XTXJiR3RIUzFwTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlFrSnFRVkZDWjI5eGFHdHBSemt5VG10Q1owbENRa0ZKUmtGRVFVdENaMmR4YUd0cVQxQlJVVVJCZDA1dlFVUkNiRUZxUWtGWWFGTnhOVWw1UzI5blRVTlFkSGMwT1RCQ1lVSTJOemREWVVWSFNsaDFabEZDTDBWeFdrZGtOa05UYW1sRGRFOXVkVTFVWWxoV1dHMTRlR040Wm10RFRWRkVWRk5RZUdGeVdsaDJUbkpyZUZVelZHdFZUVWt6TTNsNmRrWldWbEpVTkhkNFYwcERPVGswVDNOa1kxbzBLMUpIVG5OWlJIbFNOV2R0WkhJd2JrUkhaejBpTENKTlNVbERVWHBEUTBGamJXZEJkMGxDUVdkSlNVeGpXRGhwVGt4R1V6VlZkME5uV1VsTGIxcEplbW93UlVGM1RYZGFla1ZpVFVKclIwRXhWVVZCZDNkVFVWaENkMkpIVldkVmJUbDJaRU5DUkZGVFFYUkpSV042VFZOWmQwcEJXVVJXVVZGTVJFSXhRbU5JUW5OYVUwSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlZSTlFrVkhRVEZWUlVObmQwdFJXRUozWWtkVloxTlhOV3BNYWtWTVRVRnJSMEV4VlVWQ2FFMURWbFpOZDBob1kwNU5WRkYzVGtSTmQwMVVaM2hQVkVFeVYyaGpUazE2YTNkT1JFMTNUVlJuZUU5VVFUSlhha0p1VFZKemQwZFJXVVJXVVZGRVJFSktRbU5JUW5OYVUwSlRZakk1TUVsRlRrSkpRekJuVW5wTmVFcHFRV3RDWjA1V1FrRnpUVWhWUm5kalIzaHNTVVZPYkdOdVVuQmFiV3hxV1ZoU2NHSXlOR2RSV0ZZd1lVYzVlV0ZZVWpWTlVrMTNSVkZaUkZaUlVVdEVRWEJDWTBoQ2MxcFRRa3BpYlUxMVRWRnpkME5SV1VSV1VWRkhSWGRLVmxWNlFqSk5Ra0ZIUW5seFIxTk5ORGxCWjBWSFFsTjFRa0pCUVdsQk1rbEJRa3BxY0V4Nk1VRmpjVlIwYTNsS2VXZFNUV016VWtOV09HTlhhbFJ1U0dOR1FtSmFSSFZYYlVKVGNETmFTSFJtVkdwcVZIVjRlRVYwV0M4eFNEZFplVmxzTTBvMldWSmlWSHBDVUVWV2IwRXZWbWhaUkV0WU1VUjVlRTVDTUdOVVpHUnhXR3cxWkhaTlZucDBTelV4TjBsRWRsbDFWbFJhV0hCdGEwOXNSVXROWVU1RFRVVkJkMGhSV1VSV1VqQlBRa0paUlVaTWRYY3pjVVpaVFRScFlYQkpjVm96Y2pZNU5qWXZZWGw1VTNKTlFUaEhRVEZWWkVWM1JVSXZkMUZHVFVGTlFrRm1PSGRFWjFsRVZsSXdVRUZSU0M5Q1FWRkVRV2RGUjAxQmIwZERRM0ZIVTAwME9VSkJUVVJCTW1kQlRVZFZRMDFSUTBRMlkwaEZSbXcwWVZoVVVWa3laVE4yT1VkM1QwRkZXa3gxVGl0NVVtaElSa1F2TTIxbGIzbG9jRzEyVDNkblVGVnVVRmRVZUc1VE5HRjBLM0ZKZUZWRFRVY3hiV2xvUkVzeFFUTlZWRGd5VGxGNk5qQnBiVTlzVFRJM2FtSmtiMWgwTWxGbWVVWk5iU3RaYUdsa1JHdE1SakYyVEZWaFowMDJRbWRFTlRaTGVVdEJQVDBpWFgwLmV5SjBjbUZ1YzJGamRHbHZia2xrSWpvaU1qQXdNREF3TVRBeU56Y3dNVGc1T0NJc0ltOXlhV2RwYm1Gc1ZISmhibk5oWTNScGIyNUpaQ0k2SWpJd01EQXdNREV3TWpRNU9UTXlPVGtpTENKM1pXSlBjbVJsY2t4cGJtVkpkR1Z0U1dRaU9pSXlNREF3TURBd01URXpPRFkwTmpBMUlpd2lZblZ1Wkd4bFNXUWlPaUpqYjIwdWJHOXJhUzF3Y205cVpXTjBMbXh2YTJrdGJXVnpjMlZ1WjJWeUlpd2ljSEp2WkhWamRFbGtJam9pWTI5dExtZGxkSE5sYzNOcGIyNHViM0puTG5CeWIxOXpkV0pmTTE5dGIyNTBhSE1pTENKemRXSnpZM0pwY0hScGIyNUhjbTkxY0Vsa1pXNTBhV1pwWlhJaU9pSXlNVGMxTWpneE5DSXNJbkIxY21Ob1lYTmxSR0YwWlNJNk1UYzFPVGN5TnpjM09EQXdNQ3dpYjNKcFoybHVZV3hRZFhKamFHRnpaVVJoZEdVaU9qRTNOVGt6TURFNE16TXdNREFzSW1WNGNHbHlaWE5FWVhSbElqb3hOelU1TnpJNE16RTRNREF3TENKeGRXRnVkR2wwZVNJNk1Td2lkSGx3WlNJNklrRjFkRzh0VW1WdVpYZGhZbXhsSUZOMVluTmpjbWx3ZEdsdmJpSXNJbWx1UVhCd1QzZHVaWEp6YUdsd1ZIbHdaU0k2SWxCVlVrTklRVk5GUkNJc0luTnBaMjVsWkVSaGRHVWlPakUzTlRrM01qYzNPRFUwTkRVc0ltVnVkbWx5YjI1dFpXNTBJam9pVTJGdVpHSnZlQ0lzSW5SeVlXNXpZV04wYVc5dVVtVmhjMjl1SWpvaVVGVlNRMGhCVTBVaUxDSnpkRzl5WldaeWIyNTBJam9pUVZWVElpd2ljM1J2Y21WbWNtOXVkRWxrSWpvaU1UUXpORFl3SWl3aWNISnBZMlVpT2pVNU9UQXNJbU4xY25KbGJtTjVJam9pUVZWRUlpd2lZWEJ3VkhKaGJuTmhZM1JwYjI1SlpDSTZJamN3TkRnNU56UTJPVGt3TXpNNE16a3hPU0o5LmJNZk8wY1dZQ2FqRlRnNU1tdjJueVVfbEJRZnlQTTlaNXBPd19CNmpPOWp5MXF4YzQ5RGZmVFZmX1pPVTVISC0wNFc3dDNxY3pWaThLa0xlV05iaV9BIiwic2lnbmVkUmVuZXdhbEluZm8iOiJleUpoYkdjaU9pSkZVekkxTmlJc0luZzFZeUk2V3lKTlNVbEZUVlJEUTBFM1lXZEJkMGxDUVdkSlVWSTRTMGg2Wkc0MU5UUmFMMVZ2Y21Ga1RuZzVkSHBCUzBKblozRm9hMnBQVUZGUlJFRjZRakZOVlZGM1VXZFpSRlpSVVVSRVJIUkNZMGhDYzFwVFFsaGlNMHB6V2toa2NGcEhWV2RTUjFZeVdsZDRkbU5IVm5sSlJrcHNZa2RHTUdGWE9YVmplVUpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJVeE5RV3RIUVRGVlJVTjNkME5TZWxsNFJYcEJVa0puVGxaQ1FXOU5RMnRHZDJOSGVHeEpSV3gxV1hrMGVFTjZRVXBDWjA1V1FrRlpWRUZzVmxSTlFqUllSRlJKTVUxRWEzaFBWRVUxVGtSUk1VMVdiMWhFVkVrelRWUkJlRTE2UlROT1JHTjVUVEZ2ZDJkYVNYaFJSRUVyUW1kT1ZrSkJUVTFPTVVKNVlqSlJaMUpWVGtSSlJURm9XWGxDUW1OSVFXZFZNMUoyWTIxVloxbFhOV3RKUjJ4VlpGYzFiR041UWxSa1J6bDVXbE5DVTFwWFRteGhXRUl3U1VaT2NGb3lOWEJpYldONFRFUkJjVUpuVGxaQ1FYTk5TVEJHZDJOSGVHeEpSbVIyWTIxNGEyUXliR3RhVTBKRldsaGFiR0pIT1hkYVdFbG5WVzFXYzFsWVVuQmlNalY2VFZKTmQwVlJXVVJXVVZGTFJFRndRbU5JUW5OYVUwSktZbTFOZFUxUmMzZERVVmxFVmxGUlIwVjNTbFpWZWtKYVRVSk5SMEo1Y1VkVFRUUTVRV2RGUjBORGNVZFRUVFE1UVhkRlNFRXdTVUZDVG01V2RtaGpkamRwVkNzM1JYZzFkRUpOUW1keVVYTndTSHBKYzFoU2FUQlplR1psYXpkc2RqaDNSVzFxTDJKSWFWZDBUbmRLY1dNeVFtOUllbk5SYVVWcVVEZExSa2xKUzJjMFdUaDVNQzl1ZVc1MVFXMXFaMmRKU1UxSlNVTkNSRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDT0VkQk1WVmtTWGRSV1UxQ1lVRkdSRGgyYkVOT1VqQXhSRXB0YVdjNU4ySkNPRFZqSzJ4clIwdGFUVWhCUjBORGMwZEJVVlZHUW5kRlFrSkhVWGRaYWtGMFFtZG5ja0puUlVaQ1VXTjNRVzlaYUdGSVVqQmpSRzkyVERKT2JHTnVVbnBNYlVaM1kwZDRiRXh0VG5aaVV6a3paREpTZVZwNldYVmFSMVo1VFVSRlIwTkRjMGRCVVZWR1FucEJRbWhwVm05a1NGSjNUMms0ZG1JeVRucGpRelZvWTBoQ2MxcFROV3BpTWpCMllqSk9lbU5FUVhwTVdHUXpXa2hLYms1cVFYbE5TVWxDU0dkWlJGWlNNR2RDU1VsQ1JsUkRRMEZTUlhkblowVk9RbWR2Y1docmFVYzVNazVyUWxGWlFrMUpTQ3ROU1VoRVFtZG5ja0puUlVaQ1VXTkRRV3BEUW5SbmVVSnpNVXBzWWtkc2FHSnRUbXhKUnpsMVNVaFNiMkZZVFdkWk1sWjVaRWRzYldGWFRtaGtSMVZuV1c1cloxbFhOVFZKU0VKb1kyNVNOVWxIUm5wak0xWjBXbGhOWjFsWFRtcGFXRUl3V1ZjMWFscFRRblphYVVJd1lVZFZaMlJIYUd4aWFVSm9ZMGhDYzJGWFRtaFpiWGhzU1VoT01GbFhOV3RaV0VwclNVaFNiR050TVhwSlIwWjFXa05DYW1JeU5XdGhXRkp3WWpJMWVrbEhPVzFKU0ZaNldsTjNaMWt5Vm5sa1IyeHRZVmRPYUdSSFZXZGpSemx6WVZkT05VbEhSblZhUTBKcVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsSVFubFpWMDR3WVZkT2JFbElUakJaV0ZKc1lsZFdkV1JJVFhWTlJGbEhRME56UjBGUlZVWkNkMGxDUm1sd2IyUklVbmRQYVRoMlpETmtNMHh0Um5kalIzaHNURzFPZG1KVE9XcGFXRW93WVZkYWNGa3lSakJhVjBZeFpFZG9kbU50YkRCbFV6aDNTRkZaUkZaU01FOUNRbGxGUmtsR2FXOUhOSGROVFZaQk1XdDFPWHBLYlVkT1VFRldiak5sY1UxQk5FZEJNVlZrUkhkRlFpOTNVVVZCZDBsSVowUkJVVUpuYjNGb2EybEhPVEpPYTBKbmMwSkNRVWxHUVVSQlMwSm5aM0ZvYTJwUFVGRlJSRUYzVG5CQlJFSnRRV3BGUVN0eFdHNVNSVU0zYUZoSlYxWk1jMHg0ZW01cVVuQkplbEJtTjFaSWVqbFdMME5VYlRnclRFcHNjbEZsY0c1dFkxQjJSMHhPWTFnMldGQnViR05uVEVGQmFrVkJOVWxxVGxwTFoyYzFjRkUzT1d0dVJqUkpZbFJZWkV0Mk9IWjFkRWxFVFZoRWJXcFFWbFF6WkVkMlJuUnpSMUozV0U5NWQxSXlhMXBEWkZOeVptVnZkQ0lzSWsxSlNVUkdha05EUVhCNVowRjNTVUpCWjBsVlNYTkhhRkozY0RCak1tNTJWVFJaVTNsallXWlFWR3A2WWs1amQwTm5XVWxMYjFwSmVtb3dSVUYzVFhkYWVrVmlUVUpyUjBFeFZVVkJkM2RUVVZoQ2QySkhWV2RWYlRsMlpFTkNSRkZUUVhSSlJXTjZUVk5aZDBwQldVUldVVkZNUkVJeFFtTklRbk5hVTBKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVlJOUWtWSFFURlZSVU5uZDB0UldFSjNZa2RWWjFOWE5XcE1ha1ZNVFVGclIwRXhWVVZDYUUxRFZsWk5kMGhvWTA1TmFrVjNUWHBGTTAxcVFYcE9la1YzVjJoalRrMTZXWGROZWtVMVRVUkJkMDFFUVhkWGFrSXhUVlZSZDFGbldVUldVVkZFUkVSMFFtTklRbk5hVTBKWVlqTktjMXBJWkhCYVIxVm5Va2RXTWxwWGVIWmpSMVo1U1VaS2JHSkhSakJoVnpsMVkzbENSRnBZU2pCaFYxcHdXVEpHTUdGWE9YVkpSVVl4WkVkb2RtTnRiREJsVkVWTVRVRnJSMEV4VlVWRGQzZERVbnBaZUVWNlFWSkNaMDVXUWtGdlRVTnJSbmRqUjNoc1NVVnNkVmw1TkhoRGVrRktRbWRPVmtKQldWUkJiRlpVVFVoWmQwVkJXVWhMYjFwSmVtb3dRMEZSV1VaTE5FVkZRVU5KUkZsblFVVmljMUZMUXprMFVISnNWMjFhV0c1WVozUjRlbVJXU2t3NFZEQlRSMWx1WjBSU1IzQnVaMjR6VGpaUVZEaEtUVVZpTjBaRWFUUmlRbTFRYUVOdVdqTXZjM0UyVUVZdlkwZGpTMWhYYzB3MWRrOTBaVkpvZVVvME5YZ3pRVk5RTjJOUFFpdGhZVzg1TUdaamNIaFRkaTlGV2taaWJtbEJZazVuV2tkb1NXaHdTVzgwU0RaTlNVZ3pUVUpKUjBFeFZXUkZkMFZDTDNkUlNVMUJXVUpCWmpoRFFWRkJkMGgzV1VSV1VqQnFRa0puZDBadlFWVjFOMFJsYjFabmVtbEtjV3RwY0c1bGRuSXpjbkk1Y2t4S1MzTjNVbWRaU1V0M1dVSkNVVlZJUVZGRlJVOXFRVFJOUkZsSFEwTnpSMEZSVlVaQ2VrRkNhR2x3YjJSSVVuZFBhVGgyWWpKT2VtTkROV2hqU0VKeldsTTFhbUl5TUhaaU1rNTZZMFJCZWt4WFJuZGpSM2hzWTIwNWRtUkhUbWhhZWsxM1RuZFpSRlpTTUdaQ1JFRjNUR3BCYzI5RGNXZExTVmx0WVVoU01HTkViM1pNTWs1NVlrTTFhR05JUW5OYVV6VnFZakl3ZGxsWVFuZGlSMVo1WWpJNU1Ga3lSbTVOZVRWcVkyMTNkMGhSV1VSV1VqQlBRa0paUlVaRU9IWnNRMDVTTURGRVNtMXBaemszWWtJNE5XTXJiR3RIUzFwTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlFrSnFRVkZDWjI5eGFHdHBSemt5VG10Q1owbENRa0ZKUmtGRVFVdENaMmR4YUd0cVQxQlJVVVJCZDA1dlFVUkNiRUZxUWtGWWFGTnhOVWw1UzI5blRVTlFkSGMwT1RCQ1lVSTJOemREWVVWSFNsaDFabEZDTDBWeFdrZGtOa05UYW1sRGRFOXVkVTFVWWxoV1dHMTRlR040Wm10RFRWRkVWRk5RZUdGeVdsaDJUbkpyZUZVelZHdFZUVWt6TTNsNmRrWldWbEpVTkhkNFYwcERPVGswVDNOa1kxbzBLMUpIVG5OWlJIbFNOV2R0WkhJd2JrUkhaejBpTENKTlNVbERVWHBEUTBGamJXZEJkMGxDUVdkSlNVeGpXRGhwVGt4R1V6VlZkME5uV1VsTGIxcEplbW93UlVGM1RYZGFla1ZpVFVKclIwRXhWVVZCZDNkVFVWaENkMkpIVldkVmJUbDJaRU5DUkZGVFFYUkpSV042VFZOWmQwcEJXVVJXVVZGTVJFSXhRbU5JUW5OYVUwSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlZSTlFrVkhRVEZWUlVObmQwdFJXRUozWWtkVloxTlhOV3BNYWtWTVRVRnJSMEV4VlVWQ2FFMURWbFpOZDBob1kwNU5WRkYzVGtSTmQwMVVaM2hQVkVFeVYyaGpUazE2YTNkT1JFMTNUVlJuZUU5VVFUSlhha0p1VFZKemQwZFJXVVJXVVZGRVJFSktRbU5JUW5OYVUwSlRZakk1TUVsRlRrSkpRekJuVW5wTmVFcHFRV3RDWjA1V1FrRnpUVWhWUm5kalIzaHNTVVZPYkdOdVVuQmFiV3hxV1ZoU2NHSXlOR2RSV0ZZd1lVYzVlV0ZZVWpWTlVrMTNSVkZaUkZaUlVVdEVRWEJDWTBoQ2MxcFRRa3BpYlUxMVRWRnpkME5SV1VSV1VWRkhSWGRLVmxWNlFqSk5Ra0ZIUW5seFIxTk5ORGxCWjBWSFFsTjFRa0pCUVdsQk1rbEJRa3BxY0V4Nk1VRmpjVlIwYTNsS2VXZFNUV016VWtOV09HTlhhbFJ1U0dOR1FtSmFSSFZYYlVKVGNETmFTSFJtVkdwcVZIVjRlRVYwV0M4eFNEZFplVmxzTTBvMldWSmlWSHBDVUVWV2IwRXZWbWhaUkV0WU1VUjVlRTVDTUdOVVpHUnhXR3cxWkhaTlZucDBTelV4TjBsRWRsbDFWbFJhV0hCdGEwOXNSVXROWVU1RFRVVkJkMGhSV1VSV1VqQlBRa0paUlVaTWRYY3pjVVpaVFRScFlYQkpjVm96Y2pZNU5qWXZZWGw1VTNKTlFUaEhRVEZWWkVWM1JVSXZkMUZHVFVGTlFrRm1PSGRFWjFsRVZsSXdVRUZSU0M5Q1FWRkVRV2RGUjAxQmIwZERRM0ZIVTAwME9VSkJUVVJCTW1kQlRVZFZRMDFSUTBRMlkwaEZSbXcwWVZoVVVWa3laVE4yT1VkM1QwRkZXa3gxVGl0NVVtaElSa1F2TTIxbGIzbG9jRzEyVDNkblVGVnVVRmRVZUc1VE5HRjBLM0ZKZUZWRFRVY3hiV2xvUkVzeFFUTlZWRGd5VGxGNk5qQnBiVTlzVFRJM2FtSmtiMWgwTWxGbWVVWk5iU3RaYUdsa1JHdE1SakYyVEZWaFowMDJRbWRFTlRaTGVVdEJQVDBpWFgwLmV5SnZjbWxuYVc1aGJGUnlZVzV6WVdOMGFXOXVTV1FpT2lJeU1EQXdNREF4TURJME9Ua3pNams1SWl3aVlYVjBiMUpsYm1WM1VISnZaSFZqZEVsa0lqb2lZMjl0TG1kbGRITmxjM05wYjI0dWIzSm5MbkJ5YjE5emRXSmZNMTl0YjI1MGFITWlMQ0p3Y205a2RXTjBTV1FpT2lKamIyMHVaMlYwYzJWemMybHZiaTV2Y21jdWNISnZYM04xWWw4elgyMXZiblJvY3lJc0ltRjFkRzlTWlc1bGQxTjBZWFIxY3lJNk1Td2ljbVZ1WlhkaGJGQnlhV05sSWpvMU9Ua3dMQ0pqZFhKeVpXNWplU0k2SWtGVlJDSXNJbk5wWjI1bFpFUmhkR1VpT2pFM05UazNNamMzT0RVME5EVXNJbVZ1ZG1seWIyNXRaVzUwSWpvaVUyRnVaR0p2ZUNJc0luSmxZMlZ1ZEZOMVluTmpjbWx3ZEdsdmJsTjBZWEowUkdGMFpTSTZNVGMxT1RjeU56YzNPREF3TUN3aWNtVnVaWGRoYkVSaGRHVWlPakUzTlRrM01qZ3pNVGd3TURBc0ltRndjRlJ5WVc1ellXTjBhVzl1U1dRaU9pSTNNRFE0T1RjME5qazVNRE16T0RNNU1Ua2lmUS5zM3l2V2V5S0RWYlpTY2lxUlZScE1CR2twTm5RMTBsRW4tNmpYTDl5UEstWWktbkVrWE9MSXpsNEppNVZ1dEktMmtZMnZabHhqN21WWHUtMnYzTWkwUSIsInN0YXR1cyI6MX0sInZlcnNpb24iOiIyLjAiLCJzaWduZWREYXRlIjoxNzU5NzI3Nzg1NDQ1fQ.AmOrYsJMMAWUwfm43Lc6v--e7TBxPDyXNizWtw-JaxAZT2aWV8aJC90F1c8XiuKCs2F8ZAu5DHK1iLSQ7V5bKQ"
            }
            ''')

            e01_upgrade_to_1wk: dict[str, base.JSONValue] = json.loads('''
            {
            "signedPayload": "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJub3RpZmljYXRpb25UeXBlIjoiRElEX0NIQU5HRV9SRU5FV0FMX1BSRUYiLCJzdWJ0eXBlIjoiVVBHUkFERSIsIm5vdGlmaWNhdGlvblVVSUQiOiJhM2EzYjdhZS0zYmQ4LTRiOTgtYTgzZC1lNWY0MzgwYWVhYTIiLCJkYXRhIjp7ImFwcEFwcGxlSWQiOjE0NzAxNjg4NjgsImJ1bmRsZUlkIjoiY29tLmxva2ktcHJvamVjdC5sb2tpLW1lc3NlbmdlciIsImJ1bmRsZVZlcnNpb24iOiI2MzciLCJlbnZpcm9ubWVudCI6IlNhbmRib3giLCJzaWduZWRUcmFuc2FjdGlvbkluZm8iOiJleUpoYkdjaU9pSkZVekkxTmlJc0luZzFZeUk2V3lKTlNVbEZUVlJEUTBFM1lXZEJkMGxDUVdkSlVWSTRTMGg2Wkc0MU5UUmFMMVZ2Y21Ga1RuZzVkSHBCUzBKblozRm9hMnBQVUZGUlJFRjZRakZOVlZGM1VXZFpSRlpSVVVSRVJIUkNZMGhDYzFwVFFsaGlNMHB6V2toa2NGcEhWV2RTUjFZeVdsZDRkbU5IVm5sSlJrcHNZa2RHTUdGWE9YVmplVUpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJVeE5RV3RIUVRGVlJVTjNkME5TZWxsNFJYcEJVa0puVGxaQ1FXOU5RMnRHZDJOSGVHeEpSV3gxV1hrMGVFTjZRVXBDWjA1V1FrRlpWRUZzVmxSTlFqUllSRlJKTVUxRWEzaFBWRVUxVGtSUk1VMVdiMWhFVkVrelRWUkJlRTE2UlROT1JHTjVUVEZ2ZDJkYVNYaFJSRUVyUW1kT1ZrSkJUVTFPTVVKNVlqSlJaMUpWVGtSSlJURm9XWGxDUW1OSVFXZFZNMUoyWTIxVloxbFhOV3RKUjJ4VlpGYzFiR041UWxSa1J6bDVXbE5DVTFwWFRteGhXRUl3U1VaT2NGb3lOWEJpYldONFRFUkJjVUpuVGxaQ1FYTk5TVEJHZDJOSGVHeEpSbVIyWTIxNGEyUXliR3RhVTBKRldsaGFiR0pIT1hkYVdFbG5WVzFXYzFsWVVuQmlNalY2VFZKTmQwVlJXVVJXVVZGTFJFRndRbU5JUW5OYVUwSktZbTFOZFUxUmMzZERVVmxFVmxGUlIwVjNTbFpWZWtKYVRVSk5SMEo1Y1VkVFRUUTVRV2RGUjBORGNVZFRUVFE1UVhkRlNFRXdTVUZDVG01V2RtaGpkamRwVkNzM1JYZzFkRUpOUW1keVVYTndTSHBKYzFoU2FUQlplR1psYXpkc2RqaDNSVzFxTDJKSWFWZDBUbmRLY1dNeVFtOUllbk5SYVVWcVVEZExSa2xKUzJjMFdUaDVNQzl1ZVc1MVFXMXFaMmRKU1UxSlNVTkNSRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDT0VkQk1WVmtTWGRSV1UxQ1lVRkdSRGgyYkVOT1VqQXhSRXB0YVdjNU4ySkNPRFZqSzJ4clIwdGFUVWhCUjBORGMwZEJVVlZHUW5kRlFrSkhVWGRaYWtGMFFtZG5ja0puUlVaQ1VXTjNRVzlaYUdGSVVqQmpSRzkyVERKT2JHTnVVbnBNYlVaM1kwZDRiRXh0VG5aaVV6a3paREpTZVZwNldYVmFSMVo1VFVSRlIwTkRjMGRCVVZWR1FucEJRbWhwVm05a1NGSjNUMms0ZG1JeVRucGpRelZvWTBoQ2MxcFROV3BpTWpCMllqSk9lbU5FUVhwTVdHUXpXa2hLYms1cVFYbE5TVWxDU0dkWlJGWlNNR2RDU1VsQ1JsUkRRMEZTUlhkblowVk9RbWR2Y1docmFVYzVNazVyUWxGWlFrMUpTQ3ROU1VoRVFtZG5ja0puUlVaQ1VXTkRRV3BEUW5SbmVVSnpNVXBzWWtkc2FHSnRUbXhKUnpsMVNVaFNiMkZZVFdkWk1sWjVaRWRzYldGWFRtaGtSMVZuV1c1cloxbFhOVFZKU0VKb1kyNVNOVWxIUm5wak0xWjBXbGhOWjFsWFRtcGFXRUl3V1ZjMWFscFRRblphYVVJd1lVZFZaMlJIYUd4aWFVSm9ZMGhDYzJGWFRtaFpiWGhzU1VoT01GbFhOV3RaV0VwclNVaFNiR050TVhwSlIwWjFXa05DYW1JeU5XdGhXRkp3WWpJMWVrbEhPVzFKU0ZaNldsTjNaMWt5Vm5sa1IyeHRZVmRPYUdSSFZXZGpSemx6WVZkT05VbEhSblZhUTBKcVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsSVFubFpWMDR3WVZkT2JFbElUakJaV0ZKc1lsZFdkV1JJVFhWTlJGbEhRME56UjBGUlZVWkNkMGxDUm1sd2IyUklVbmRQYVRoMlpETmtNMHh0Um5kalIzaHNURzFPZG1KVE9XcGFXRW93WVZkYWNGa3lSakJhVjBZeFpFZG9kbU50YkRCbFV6aDNTRkZaUkZaU01FOUNRbGxGUmtsR2FXOUhOSGROVFZaQk1XdDFPWHBLYlVkT1VFRldiak5sY1UxQk5FZEJNVlZrUkhkRlFpOTNVVVZCZDBsSVowUkJVVUpuYjNGb2EybEhPVEpPYTBKbmMwSkNRVWxHUVVSQlMwSm5aM0ZvYTJwUFVGRlJSRUYzVG5CQlJFSnRRV3BGUVN0eFdHNVNSVU0zYUZoSlYxWk1jMHg0ZW01cVVuQkplbEJtTjFaSWVqbFdMME5VYlRnclRFcHNjbEZsY0c1dFkxQjJSMHhPWTFnMldGQnViR05uVEVGQmFrVkJOVWxxVGxwTFoyYzFjRkUzT1d0dVJqUkpZbFJZWkV0Mk9IWjFkRWxFVFZoRWJXcFFWbFF6WkVkMlJuUnpSMUozV0U5NWQxSXlhMXBEWkZOeVptVnZkQ0lzSWsxSlNVUkdha05EUVhCNVowRjNTVUpCWjBsVlNYTkhhRkozY0RCak1tNTJWVFJaVTNsallXWlFWR3A2WWs1amQwTm5XVWxMYjFwSmVtb3dSVUYzVFhkYWVrVmlUVUpyUjBFeFZVVkJkM2RUVVZoQ2QySkhWV2RWYlRsMlpFTkNSRkZUUVhSSlJXTjZUVk5aZDBwQldVUldVVkZNUkVJeFFtTklRbk5hVTBKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVlJOUWtWSFFURlZSVU5uZDB0UldFSjNZa2RWWjFOWE5XcE1ha1ZNVFVGclIwRXhWVVZDYUUxRFZsWk5kMGhvWTA1TmFrVjNUWHBGTTAxcVFYcE9la1YzVjJoalRrMTZXWGROZWtVMVRVUkJkMDFFUVhkWGFrSXhUVlZSZDFGbldVUldVVkZFUkVSMFFtTklRbk5hVTBKWVlqTktjMXBJWkhCYVIxVm5Va2RXTWxwWGVIWmpSMVo1U1VaS2JHSkhSakJoVnpsMVkzbENSRnBZU2pCaFYxcHdXVEpHTUdGWE9YVkpSVVl4WkVkb2RtTnRiREJsVkVWTVRVRnJSMEV4VlVWRGQzZERVbnBaZUVWNlFWSkNaMDVXUWtGdlRVTnJSbmRqUjNoc1NVVnNkVmw1TkhoRGVrRktRbWRPVmtKQldWUkJiRlpVVFVoWmQwVkJXVWhMYjFwSmVtb3dRMEZSV1VaTE5FVkZRVU5KUkZsblFVVmljMUZMUXprMFVISnNWMjFhV0c1WVozUjRlbVJXU2t3NFZEQlRSMWx1WjBSU1IzQnVaMjR6VGpaUVZEaEtUVVZpTjBaRWFUUmlRbTFRYUVOdVdqTXZjM0UyVUVZdlkwZGpTMWhYYzB3MWRrOTBaVkpvZVVvME5YZ3pRVk5RTjJOUFFpdGhZVzg1TUdaamNIaFRkaTlGV2taaWJtbEJZazVuV2tkb1NXaHdTVzgwU0RaTlNVZ3pUVUpKUjBFeFZXUkZkMFZDTDNkUlNVMUJXVUpCWmpoRFFWRkJkMGgzV1VSV1VqQnFRa0puZDBadlFWVjFOMFJsYjFabmVtbEtjV3RwY0c1bGRuSXpjbkk1Y2t4S1MzTjNVbWRaU1V0M1dVSkNVVlZJUVZGRlJVOXFRVFJOUkZsSFEwTnpSMEZSVlVaQ2VrRkNhR2x3YjJSSVVuZFBhVGgyWWpKT2VtTkROV2hqU0VKeldsTTFhbUl5TUhaaU1rNTZZMFJCZWt4WFJuZGpSM2hzWTIwNWRtUkhUbWhhZWsxM1RuZFpSRlpTTUdaQ1JFRjNUR3BCYzI5RGNXZExTVmx0WVVoU01HTkViM1pNTWs1NVlrTTFhR05JUW5OYVV6VnFZakl3ZGxsWVFuZGlSMVo1WWpJNU1Ga3lSbTVOZVRWcVkyMTNkMGhSV1VSV1VqQlBRa0paUlVaRU9IWnNRMDVTTURGRVNtMXBaemszWWtJNE5XTXJiR3RIUzFwTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlFrSnFRVkZDWjI5eGFHdHBSemt5VG10Q1owbENRa0ZKUmtGRVFVdENaMmR4YUd0cVQxQlJVVVJCZDA1dlFVUkNiRUZxUWtGWWFGTnhOVWw1UzI5blRVTlFkSGMwT1RCQ1lVSTJOemREWVVWSFNsaDFabEZDTDBWeFdrZGtOa05UYW1sRGRFOXVkVTFVWWxoV1dHMTRlR040Wm10RFRWRkVWRk5RZUdGeVdsaDJUbkpyZUZVelZHdFZUVWt6TTNsNmRrWldWbEpVTkhkNFYwcERPVGswVDNOa1kxbzBLMUpIVG5OWlJIbFNOV2R0WkhJd2JrUkhaejBpTENKTlNVbERVWHBEUTBGamJXZEJkMGxDUVdkSlNVeGpXRGhwVGt4R1V6VlZkME5uV1VsTGIxcEplbW93UlVGM1RYZGFla1ZpVFVKclIwRXhWVVZCZDNkVFVWaENkMkpIVldkVmJUbDJaRU5DUkZGVFFYUkpSV042VFZOWmQwcEJXVVJXVVZGTVJFSXhRbU5JUW5OYVUwSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlZSTlFrVkhRVEZWUlVObmQwdFJXRUozWWtkVloxTlhOV3BNYWtWTVRVRnJSMEV4VlVWQ2FFMURWbFpOZDBob1kwNU5WRkYzVGtSTmQwMVVaM2hQVkVFeVYyaGpUazE2YTNkT1JFMTNUVlJuZUU5VVFUSlhha0p1VFZKemQwZFJXVVJXVVZGRVJFSktRbU5JUW5OYVUwSlRZakk1TUVsRlRrSkpRekJuVW5wTmVFcHFRV3RDWjA1V1FrRnpUVWhWUm5kalIzaHNTVVZPYkdOdVVuQmFiV3hxV1ZoU2NHSXlOR2RSV0ZZd1lVYzVlV0ZZVWpWTlVrMTNSVkZaUkZaUlVVdEVRWEJDWTBoQ2MxcFRRa3BpYlUxMVRWRnpkME5SV1VSV1VWRkhSWGRLVmxWNlFqSk5Ra0ZIUW5seFIxTk5ORGxCWjBWSFFsTjFRa0pCUVdsQk1rbEJRa3BxY0V4Nk1VRmpjVlIwYTNsS2VXZFNUV016VWtOV09HTlhhbFJ1U0dOR1FtSmFSSFZYYlVKVGNETmFTSFJtVkdwcVZIVjRlRVYwV0M4eFNEZFplVmxzTTBvMldWSmlWSHBDVUVWV2IwRXZWbWhaUkV0WU1VUjVlRTVDTUdOVVpHUnhXR3cxWkhaTlZucDBTelV4TjBsRWRsbDFWbFJhV0hCdGEwOXNSVXROWVU1RFRVVkJkMGhSV1VSV1VqQlBRa0paUlVaTWRYY3pjVVpaVFRScFlYQkpjVm96Y2pZNU5qWXZZWGw1VTNKTlFUaEhRVEZWWkVWM1JVSXZkMUZHVFVGTlFrRm1PSGRFWjFsRVZsSXdVRUZSU0M5Q1FWRkVRV2RGUjAxQmIwZERRM0ZIVTAwME9VSkJUVVJCTW1kQlRVZFZRMDFSUTBRMlkwaEZSbXcwWVZoVVVWa3laVE4yT1VkM1QwRkZXa3gxVGl0NVVtaElSa1F2TTIxbGIzbG9jRzEyVDNkblVGVnVVRmRVZUc1VE5HRjBLM0ZKZUZWRFRVY3hiV2xvUkVzeFFUTlZWRGd5VGxGNk5qQnBiVTlzVFRJM2FtSmtiMWgwTWxGbWVVWk5iU3RaYUdsa1JHdE1SakYyVEZWaFowMDJRbWRFTlRaTGVVdEJQVDBpWFgwLmV5SjBjbUZ1YzJGamRHbHZia2xrSWpvaU1qQXdNREF3TVRBeU56Y3dNVGt5T0NJc0ltOXlhV2RwYm1Gc1ZISmhibk5oWTNScGIyNUpaQ0k2SWpJd01EQXdNREV3TWpRNU9UTXlPVGtpTENKM1pXSlBjbVJsY2t4cGJtVkpkR1Z0U1dRaU9pSXlNREF3TURBd01URTBNakF5TVRRd0lpd2lZblZ1Wkd4bFNXUWlPaUpqYjIwdWJHOXJhUzF3Y205cVpXTjBMbXh2YTJrdGJXVnpjMlZ1WjJWeUlpd2ljSEp2WkhWamRFbGtJam9pWTI5dExtZGxkSE5sYzNOcGIyNHViM0puTG5CeWIxOXpkV0lpTENKemRXSnpZM0pwY0hScGIyNUhjbTkxY0Vsa1pXNTBhV1pwWlhJaU9pSXlNVGMxTWpneE5DSXNJbkIxY21Ob1lYTmxSR0YwWlNJNk1UYzFPVGN5TnpjNU1EQXdNQ3dpYjNKcFoybHVZV3hRZFhKamFHRnpaVVJoZEdVaU9qRTNOVGt6TURFNE16TXdNREFzSW1WNGNHbHlaWE5FWVhSbElqb3hOelU1TnpJM09UY3dNREF3TENKeGRXRnVkR2wwZVNJNk1Td2lkSGx3WlNJNklrRjFkRzh0VW1WdVpYZGhZbXhsSUZOMVluTmpjbWx3ZEdsdmJpSXNJbWx1UVhCd1QzZHVaWEp6YUdsd1ZIbHdaU0k2SWxCVlVrTklRVk5GUkNJc0luTnBaMjVsWkVSaGRHVWlPakUzTlRrM01qYzNPVGs0TVRBc0ltVnVkbWx5YjI1dFpXNTBJam9pVTJGdVpHSnZlQ0lzSW5SeVlXNXpZV04wYVc5dVVtVmhjMjl1SWpvaVVGVlNRMGhCVTBVaUxDSnpkRzl5WldaeWIyNTBJam9pUVZWVElpd2ljM1J2Y21WbWNtOXVkRWxrSWpvaU1UUXpORFl3SWl3aWNISnBZMlVpT2pFNU9UQXNJbU4xY25KbGJtTjVJam9pUVZWRUlpd2lZWEJ3VkhKaGJuTmhZM1JwYjI1SlpDSTZJamN3TkRnNU56UTJPVGt3TXpNNE16a3hPU0o5LlBIeVZ2RGxtam9PM0tGajlVX0pzQTdweElwNzMwR0l3SXNrb2c1UGZzcmNiX0hacFhjVTFMVU9aWWtRSmp0ZlZQeWZ1bk1wSUpBdW9taGZjWGlHazFnIiwic2lnbmVkUmVuZXdhbEluZm8iOiJleUpoYkdjaU9pSkZVekkxTmlJc0luZzFZeUk2V3lKTlNVbEZUVlJEUTBFM1lXZEJkMGxDUVdkSlVWSTRTMGg2Wkc0MU5UUmFMMVZ2Y21Ga1RuZzVkSHBCUzBKblozRm9hMnBQVUZGUlJFRjZRakZOVlZGM1VXZFpSRlpSVVVSRVJIUkNZMGhDYzFwVFFsaGlNMHB6V2toa2NGcEhWV2RTUjFZeVdsZDRkbU5IVm5sSlJrcHNZa2RHTUdGWE9YVmplVUpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJVeE5RV3RIUVRGVlJVTjNkME5TZWxsNFJYcEJVa0puVGxaQ1FXOU5RMnRHZDJOSGVHeEpSV3gxV1hrMGVFTjZRVXBDWjA1V1FrRlpWRUZzVmxSTlFqUllSRlJKTVUxRWEzaFBWRVUxVGtSUk1VMVdiMWhFVkVrelRWUkJlRTE2UlROT1JHTjVUVEZ2ZDJkYVNYaFJSRUVyUW1kT1ZrSkJUVTFPTVVKNVlqSlJaMUpWVGtSSlJURm9XWGxDUW1OSVFXZFZNMUoyWTIxVloxbFhOV3RKUjJ4VlpGYzFiR041UWxSa1J6bDVXbE5DVTFwWFRteGhXRUl3U1VaT2NGb3lOWEJpYldONFRFUkJjVUpuVGxaQ1FYTk5TVEJHZDJOSGVHeEpSbVIyWTIxNGEyUXliR3RhVTBKRldsaGFiR0pIT1hkYVdFbG5WVzFXYzFsWVVuQmlNalY2VFZKTmQwVlJXVVJXVVZGTFJFRndRbU5JUW5OYVUwSktZbTFOZFUxUmMzZERVVmxFVmxGUlIwVjNTbFpWZWtKYVRVSk5SMEo1Y1VkVFRUUTVRV2RGUjBORGNVZFRUVFE1UVhkRlNFRXdTVUZDVG01V2RtaGpkamRwVkNzM1JYZzFkRUpOUW1keVVYTndTSHBKYzFoU2FUQlplR1psYXpkc2RqaDNSVzFxTDJKSWFWZDBUbmRLY1dNeVFtOUllbk5SYVVWcVVEZExSa2xKUzJjMFdUaDVNQzl1ZVc1MVFXMXFaMmRKU1UxSlNVTkNSRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDT0VkQk1WVmtTWGRSV1UxQ1lVRkdSRGgyYkVOT1VqQXhSRXB0YVdjNU4ySkNPRFZqSzJ4clIwdGFUVWhCUjBORGMwZEJVVlZHUW5kRlFrSkhVWGRaYWtGMFFtZG5ja0puUlVaQ1VXTjNRVzlaYUdGSVVqQmpSRzkyVERKT2JHTnVVbnBNYlVaM1kwZDRiRXh0VG5aaVV6a3paREpTZVZwNldYVmFSMVo1VFVSRlIwTkRjMGRCVVZWR1FucEJRbWhwVm05a1NGSjNUMms0ZG1JeVRucGpRelZvWTBoQ2MxcFROV3BpTWpCMllqSk9lbU5FUVhwTVdHUXpXa2hLYms1cVFYbE5TVWxDU0dkWlJGWlNNR2RDU1VsQ1JsUkRRMEZTUlhkblowVk9RbWR2Y1docmFVYzVNazVyUWxGWlFrMUpTQ3ROU1VoRVFtZG5ja0puUlVaQ1VXTkRRV3BEUW5SbmVVSnpNVXBzWWtkc2FHSnRUbXhKUnpsMVNVaFNiMkZZVFdkWk1sWjVaRWRzYldGWFRtaGtSMVZuV1c1cloxbFhOVFZKU0VKb1kyNVNOVWxIUm5wak0xWjBXbGhOWjFsWFRtcGFXRUl3V1ZjMWFscFRRblphYVVJd1lVZFZaMlJIYUd4aWFVSm9ZMGhDYzJGWFRtaFpiWGhzU1VoT01GbFhOV3RaV0VwclNVaFNiR050TVhwSlIwWjFXa05DYW1JeU5XdGhXRkp3WWpJMWVrbEhPVzFKU0ZaNldsTjNaMWt5Vm5sa1IyeHRZVmRPYUdSSFZXZGpSemx6WVZkT05VbEhSblZhUTBKcVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsSVFubFpWMDR3WVZkT2JFbElUakJaV0ZKc1lsZFdkV1JJVFhWTlJGbEhRME56UjBGUlZVWkNkMGxDUm1sd2IyUklVbmRQYVRoMlpETmtNMHh0Um5kalIzaHNURzFPZG1KVE9XcGFXRW93WVZkYWNGa3lSakJhVjBZeFpFZG9kbU50YkRCbFV6aDNTRkZaUkZaU01FOUNRbGxGUmtsR2FXOUhOSGROVFZaQk1XdDFPWHBLYlVkT1VFRldiak5sY1UxQk5FZEJNVlZrUkhkRlFpOTNVVVZCZDBsSVowUkJVVUpuYjNGb2EybEhPVEpPYTBKbmMwSkNRVWxHUVVSQlMwSm5aM0ZvYTJwUFVGRlJSRUYzVG5CQlJFSnRRV3BGUVN0eFdHNVNSVU0zYUZoSlYxWk1jMHg0ZW01cVVuQkplbEJtTjFaSWVqbFdMME5VYlRnclRFcHNjbEZsY0c1dFkxQjJSMHhPWTFnMldGQnViR05uVEVGQmFrVkJOVWxxVGxwTFoyYzFjRkUzT1d0dVJqUkpZbFJZWkV0Mk9IWjFkRWxFVFZoRWJXcFFWbFF6WkVkMlJuUnpSMUozV0U5NWQxSXlhMXBEWkZOeVptVnZkQ0lzSWsxSlNVUkdha05EUVhCNVowRjNTVUpCWjBsVlNYTkhhRkozY0RCak1tNTJWVFJaVTNsallXWlFWR3A2WWs1amQwTm5XVWxMYjFwSmVtb3dSVUYzVFhkYWVrVmlUVUpyUjBFeFZVVkJkM2RUVVZoQ2QySkhWV2RWYlRsMlpFTkNSRkZUUVhSSlJXTjZUVk5aZDBwQldVUldVVkZNUkVJeFFtTklRbk5hVTBKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVlJOUWtWSFFURlZSVU5uZDB0UldFSjNZa2RWWjFOWE5XcE1ha1ZNVFVGclIwRXhWVVZDYUUxRFZsWk5kMGhvWTA1TmFrVjNUWHBGTTAxcVFYcE9la1YzVjJoalRrMTZXWGROZWtVMVRVUkJkMDFFUVhkWGFrSXhUVlZSZDFGbldVUldVVkZFUkVSMFFtTklRbk5hVTBKWVlqTktjMXBJWkhCYVIxVm5Va2RXTWxwWGVIWmpSMVo1U1VaS2JHSkhSakJoVnpsMVkzbENSRnBZU2pCaFYxcHdXVEpHTUdGWE9YVkpSVVl4WkVkb2RtTnRiREJsVkVWTVRVRnJSMEV4VlVWRGQzZERVbnBaZUVWNlFWSkNaMDVXUWtGdlRVTnJSbmRqUjNoc1NVVnNkVmw1TkhoRGVrRktRbWRPVmtKQldWUkJiRlpVVFVoWmQwVkJXVWhMYjFwSmVtb3dRMEZSV1VaTE5FVkZRVU5KUkZsblFVVmljMUZMUXprMFVISnNWMjFhV0c1WVozUjRlbVJXU2t3NFZEQlRSMWx1WjBSU1IzQnVaMjR6VGpaUVZEaEtUVVZpTjBaRWFUUmlRbTFRYUVOdVdqTXZjM0UyVUVZdlkwZGpTMWhYYzB3MWRrOTBaVkpvZVVvME5YZ3pRVk5RTjJOUFFpdGhZVzg1TUdaamNIaFRkaTlGV2taaWJtbEJZazVuV2tkb1NXaHdTVzgwU0RaTlNVZ3pUVUpKUjBFeFZXUkZkMFZDTDNkUlNVMUJXVUpCWmpoRFFWRkJkMGgzV1VSV1VqQnFRa0puZDBadlFWVjFOMFJsYjFabmVtbEtjV3RwY0c1bGRuSXpjbkk1Y2t4S1MzTjNVbWRaU1V0M1dVSkNVVlZJUVZGRlJVOXFRVFJOUkZsSFEwTnpSMEZSVlVaQ2VrRkNhR2x3YjJSSVVuZFBhVGgyWWpKT2VtTkROV2hqU0VKeldsTTFhbUl5TUhaaU1rNTZZMFJCZWt4WFJuZGpSM2hzWTIwNWRtUkhUbWhhZWsxM1RuZFpSRlpTTUdaQ1JFRjNUR3BCYzI5RGNXZExTVmx0WVVoU01HTkViM1pNTWs1NVlrTTFhR05JUW5OYVV6VnFZakl3ZGxsWVFuZGlSMVo1WWpJNU1Ga3lSbTVOZVRWcVkyMTNkMGhSV1VSV1VqQlBRa0paUlVaRU9IWnNRMDVTTURGRVNtMXBaemszWWtJNE5XTXJiR3RIUzFwTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlFrSnFRVkZDWjI5eGFHdHBSemt5VG10Q1owbENRa0ZKUmtGRVFVdENaMmR4YUd0cVQxQlJVVVJCZDA1dlFVUkNiRUZxUWtGWWFGTnhOVWw1UzI5blRVTlFkSGMwT1RCQ1lVSTJOemREWVVWSFNsaDFabEZDTDBWeFdrZGtOa05UYW1sRGRFOXVkVTFVWWxoV1dHMTRlR040Wm10RFRWRkVWRk5RZUdGeVdsaDJUbkpyZUZVelZHdFZUVWt6TTNsNmRrWldWbEpVTkhkNFYwcERPVGswVDNOa1kxbzBLMUpIVG5OWlJIbFNOV2R0WkhJd2JrUkhaejBpTENKTlNVbERVWHBEUTBGamJXZEJkMGxDUVdkSlNVeGpXRGhwVGt4R1V6VlZkME5uV1VsTGIxcEplbW93UlVGM1RYZGFla1ZpVFVKclIwRXhWVVZCZDNkVFVWaENkMkpIVldkVmJUbDJaRU5DUkZGVFFYUkpSV042VFZOWmQwcEJXVVJXVVZGTVJFSXhRbU5JUW5OYVUwSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlZSTlFrVkhRVEZWUlVObmQwdFJXRUozWWtkVloxTlhOV3BNYWtWTVRVRnJSMEV4VlVWQ2FFMURWbFpOZDBob1kwNU5WRkYzVGtSTmQwMVVaM2hQVkVFeVYyaGpUazE2YTNkT1JFMTNUVlJuZUU5VVFUSlhha0p1VFZKemQwZFJXVVJXVVZGRVJFSktRbU5JUW5OYVUwSlRZakk1TUVsRlRrSkpRekJuVW5wTmVFcHFRV3RDWjA1V1FrRnpUVWhWUm5kalIzaHNTVVZPYkdOdVVuQmFiV3hxV1ZoU2NHSXlOR2RSV0ZZd1lVYzVlV0ZZVWpWTlVrMTNSVkZaUkZaUlVVdEVRWEJDWTBoQ2MxcFRRa3BpYlUxMVRWRnpkME5SV1VSV1VWRkhSWGRLVmxWNlFqSk5Ra0ZIUW5seFIxTk5ORGxCWjBWSFFsTjFRa0pCUVdsQk1rbEJRa3BxY0V4Nk1VRmpjVlIwYTNsS2VXZFNUV016VWtOV09HTlhhbFJ1U0dOR1FtSmFSSFZYYlVKVGNETmFTSFJtVkdwcVZIVjRlRVYwV0M4eFNEZFplVmxzTTBvMldWSmlWSHBDVUVWV2IwRXZWbWhaUkV0WU1VUjVlRTVDTUdOVVpHUnhXR3cxWkhaTlZucDBTelV4TjBsRWRsbDFWbFJhV0hCdGEwOXNSVXROWVU1RFRVVkJkMGhSV1VSV1VqQlBRa0paUlVaTWRYY3pjVVpaVFRScFlYQkpjVm96Y2pZNU5qWXZZWGw1VTNKTlFUaEhRVEZWWkVWM1JVSXZkMUZHVFVGTlFrRm1PSGRFWjFsRVZsSXdVRUZSU0M5Q1FWRkVRV2RGUjAxQmIwZERRM0ZIVTAwME9VSkJUVVJCTW1kQlRVZFZRMDFSUTBRMlkwaEZSbXcwWVZoVVVWa3laVE4yT1VkM1QwRkZXa3gxVGl0NVVtaElSa1F2TTIxbGIzbG9jRzEyVDNkblVGVnVVRmRVZUc1VE5HRjBLM0ZKZUZWRFRVY3hiV2xvUkVzeFFUTlZWRGd5VGxGNk5qQnBiVTlzVFRJM2FtSmtiMWgwTWxGbWVVWk5iU3RaYUdsa1JHdE1SakYyVEZWaFowMDJRbWRFTlRaTGVVdEJQVDBpWFgwLmV5SnZjbWxuYVc1aGJGUnlZVzV6WVdOMGFXOXVTV1FpT2lJeU1EQXdNREF4TURJME9Ua3pNams1SWl3aVlYVjBiMUpsYm1WM1VISnZaSFZqZEVsa0lqb2lZMjl0TG1kbGRITmxjM05wYjI0dWIzSm5MbkJ5YjE5emRXSWlMQ0p3Y205a2RXTjBTV1FpT2lKamIyMHVaMlYwYzJWemMybHZiaTV2Y21jdWNISnZYM04xWWlJc0ltRjFkRzlTWlc1bGQxTjBZWFIxY3lJNk1Td2ljbVZ1WlhkaGJGQnlhV05sSWpveE9Ua3dMQ0pqZFhKeVpXNWplU0k2SWtGVlJDSXNJbk5wWjI1bFpFUmhkR1VpT2pFM05UazNNamMzT1RrNE1UQXNJbVZ1ZG1seWIyNXRaVzUwSWpvaVUyRnVaR0p2ZUNJc0luSmxZMlZ1ZEZOMVluTmpjbWx3ZEdsdmJsTjBZWEowUkdGMFpTSTZNVGMxT1RjeU56YzNPREF3TUN3aWNtVnVaWGRoYkVSaGRHVWlPakUzTlRrM01qYzVOekF3TURBc0ltRndjRlJ5WVc1ellXTjBhVzl1U1dRaU9pSTNNRFE0T1RjME5qazVNRE16T0RNNU1Ua2lmUS4taVgwU3RjVzRseHg4ekNza2wxU0ZmLUhOT1Y1S2l3ZGRLSjQyWG1XYUZDc0V1QUJ0QVdzekJFc0p1NE9JUVRIaDZhYW1ZeDVDa29CVGVVeTZoc1J0ZyIsInN0YXR1cyI6MX0sInZlcnNpb24iOiIyLjAiLCJzaWduZWREYXRlIjoxNzU5NzI3Nzk5ODEwfQ.ZYwnuA02u4fqEw2pyVwTIPQV3KOWPjyGdjwVkAgJrZsvepyvwztss5kWh13jBu6EWbk9X6Bs8YjhHa_NNlDV1A"
            }
            ''')

            e02_disable_auto_renew: dict[str, base.JSONValue] = json.loads('''
            {
            "signedPayload": "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJub3RpZmljYXRpb25UeXBlIjoiRElEX0NIQU5HRV9SRU5FV0FMX1NUQVRVUyIsInN1YnR5cGUiOiJBVVRPX1JFTkVXX0RJU0FCTEVEIiwibm90aWZpY2F0aW9uVVVJRCI6IjZhODI1MWQyLTQyNWQtNDlhMy04MWI2LTUxN2NlZmM0YTVlYSIsImRhdGEiOnsiYXBwQXBwbGVJZCI6MTQ3MDE2ODg2OCwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwiYnVuZGxlVmVyc2lvbiI6IjYzNyIsImVudmlyb25tZW50IjoiU2FuZGJveCIsInNpZ25lZFRyYW5zYWN0aW9uSW5mbyI6ImV5SmhiR2NpT2lKRlV6STFOaUlzSW5nMVl5STZXeUpOU1VsRlRWUkRRMEUzWVdkQmQwbENRV2RKVVZJNFMwaDZaRzQxTlRSYUwxVnZjbUZrVG5nNWRIcEJTMEpuWjNGb2EycFBVRkZSUkVGNlFqRk5WVkYzVVdkWlJGWlJVVVJFUkhSQ1kwaENjMXBUUWxoaU0wcHpXa2hrY0ZwSFZXZFNSMVl5V2xkNGRtTkhWbmxKUmtwc1lrZEdNR0ZYT1hWamVVSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlV4TlFXdEhRVEZWUlVOM2QwTlNlbGw0UlhwQlVrSm5UbFpDUVc5TlEydEdkMk5IZUd4SlJXeDFXWGswZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOUWpSWVJGUkpNVTFFYTNoUFZFVTFUa1JSTVUxV2IxaEVWRWt6VFZSQmVFMTZSVE5PUkdONVRURnZkMmRhU1hoUlJFRXJRbWRPVmtKQlRVMU9NVUo1WWpKUloxSlZUa1JKUlRGb1dYbENRbU5JUVdkVk0xSjJZMjFWWjFsWE5XdEpSMnhWWkZjMWJHTjVRbFJrUnpsNVdsTkNVMXBYVG14aFdFSXdTVVpPY0ZveU5YQmliV040VEVSQmNVSm5UbFpDUVhOTlNUQkdkMk5IZUd4SlJtUjJZMjE0YTJReWJHdGFVMEpGV2xoYWJHSkhPWGRhV0VsblZXMVdjMWxZVW5CaU1qVjZUVkpOZDBWUldVUldVVkZMUkVGd1FtTklRbk5hVTBKS1ltMU5kVTFSYzNkRFVWbEVWbEZSUjBWM1NsWlZla0phVFVKTlIwSjVjVWRUVFRRNVFXZEZSME5EY1VkVFRUUTVRWGRGU0VFd1NVRkNUbTVXZG1oamRqZHBWQ3MzUlhnMWRFSk5RbWR5VVhOd1NIcEpjMWhTYVRCWmVHWmxhemRzZGpoM1JXMXFMMkpJYVZkMFRuZEtjV015UW05SWVuTlJhVVZxVURkTFJrbEpTMmMwV1RoNU1DOXVlVzUxUVcxcVoyZEpTVTFKU1VOQ1JFRk5RbWRPVmtoU1RVSkJaamhGUVdwQlFVMUNPRWRCTVZWa1NYZFJXVTFDWVVGR1JEaDJiRU5PVWpBeFJFcHRhV2M1TjJKQ09EVmpLMnhyUjB0YVRVaEJSME5EYzBkQlVWVkdRbmRGUWtKSFVYZFpha0YwUW1kbmNrSm5SVVpDVVdOM1FXOVphR0ZJVWpCalJHOTJUREpPYkdOdVVucE1iVVozWTBkNGJFeHRUblppVXprelpESlNlVnA2V1hWYVIxWjVUVVJGUjBORGMwZEJVVlZHUW5wQlFtaHBWbTlrU0ZKM1QyazRkbUl5VG5walF6Vm9ZMGhDYzFwVE5XcGlNakIyWWpKT2VtTkVRWHBNV0dReldraEtiazVxUVhsTlNVbENTR2RaUkZaU01HZENTVWxDUmxSRFEwRlNSWGRuWjBWT1FtZHZjV2hyYVVjNU1rNXJRbEZaUWsxSlNDdE5TVWhFUW1kbmNrSm5SVVpDVVdORFFXcERRblJuZVVKek1VcHNZa2RzYUdKdFRteEpSemwxU1VoU2IyRllUV2RaTWxaNVpFZHNiV0ZYVG1oa1IxVm5XVzVyWjFsWE5UVkpTRUpvWTI1U05VbEhSbnBqTTFaMFdsaE5aMWxYVG1wYVdFSXdXVmMxYWxwVFFuWmFhVUl3WVVkVloyUkhhR3hpYVVKb1kwaENjMkZYVG1oWmJYaHNTVWhPTUZsWE5XdFpXRXByU1VoU2JHTnRNWHBKUjBaMVdrTkNhbUl5Tld0aFdGSndZakkxZWtsSE9XMUpTRlo2V2xOM1oxa3lWbmxrUjJ4dFlWZE9hR1JIVldkalJ6bHpZVmRPTlVsSFJuVmFRMEpxV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxJUW5sWlYwNHdZVmRPYkVsSVRqQlpXRkpzWWxkV2RXUklUWFZOUkZsSFEwTnpSMEZSVlVaQ2QwbENSbWx3YjJSSVVuZFBhVGgyWkROa00weHRSbmRqUjNoc1RHMU9kbUpUT1dwYVdFb3dZVmRhY0ZreVJqQmFWMFl4WkVkb2RtTnRiREJsVXpoM1NGRlpSRlpTTUU5Q1FsbEZSa2xHYVc5SE5IZE5UVlpCTVd0MU9YcEtiVWRPVUVGV2JqTmxjVTFCTkVkQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlVVSm5iM0ZvYTJsSE9USk9hMEpuYzBKQ1FVbEdRVVJCUzBKblozRm9hMnBQVUZGUlJFRjNUbkJCUkVKdFFXcEZRU3R4V0c1U1JVTTNhRmhKVjFaTWMweDRlbTVxVW5CSmVsQm1OMVpJZWpsV0wwTlViVGdyVEVwc2NsRmxjRzV0WTFCMlIweE9ZMWcyV0ZCdWJHTm5URUZCYWtWQk5VbHFUbHBMWjJjMWNGRTNPV3R1UmpSSllsUllaRXQyT0haMWRFbEVUVmhFYldwUVZsUXpaRWQyUm5SelIxSjNXRTk1ZDFJeWExcERaRk55Wm1WdmRDSXNJazFKU1VSR2FrTkRRWEI1WjBGM1NVSkJaMGxWU1hOSGFGSjNjREJqTW01MlZUUlpVM2xqWVdaUVZHcDZZazVqZDBObldVbExiMXBKZW1vd1JVRjNUWGRhZWtWaVRVSnJSMEV4VlVWQmQzZFRVVmhDZDJKSFZXZFZiVGwyWkVOQ1JGRlRRWFJKUldONlRWTlpkMHBCV1VSV1VWRk1SRUl4UW1OSVFuTmFVMEpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJWUk5Ra1ZIUVRGVlJVTm5kMHRSV0VKM1lrZFZaMU5YTldwTWFrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmQwaG9ZMDVOYWtWM1RYcEZNMDFxUVhwT2VrVjNWMmhqVGsxNldYZE5la1UxVFVSQmQwMUVRWGRYYWtJeFRWVlJkMUZuV1VSV1VWRkVSRVIwUW1OSVFuTmFVMEpZWWpOS2MxcElaSEJhUjFWblVrZFdNbHBYZUhaalIxWjVTVVpLYkdKSFJqQmhWemwxWTNsQ1JGcFlTakJoVjFwd1dUSkdNR0ZYT1hWSlJVWXhaRWRvZG1OdGJEQmxWRVZNVFVGclIwRXhWVVZEZDNkRFVucFplRVY2UVZKQ1owNVdRa0Z2VFVOclJuZGpSM2hzU1VWc2RWbDVOSGhEZWtGS1FtZE9Wa0pCV1ZSQmJGWlVUVWhaZDBWQldVaExiMXBKZW1vd1EwRlJXVVpMTkVWRlFVTkpSRmxuUVVWaWMxRkxRemswVUhKc1YyMWFXRzVZWjNSNGVtUldTa3c0VkRCVFIxbHVaMFJTUjNCdVoyNHpUalpRVkRoS1RVVmlOMFpFYVRSaVFtMVFhRU51V2pNdmMzRTJVRVl2WTBkalMxaFhjMHcxZGs5MFpWSm9lVW8wTlhnelFWTlFOMk5QUWl0aFlXODVNR1pqY0hoVGRpOUZXa1ppYm1sQllrNW5Xa2RvU1dod1NXODBTRFpOU1VnelRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaamhEUVZGQmQwaDNXVVJXVWpCcVFrSm5kMFp2UVZWMU4wUmxiMVpuZW1sS2NXdHBjRzVsZG5JemNuSTVja3hLUzNOM1VtZFpTVXQzV1VKQ1VWVklRVkZGUlU5cVFUUk5SRmxIUTBOelIwRlJWVVpDZWtGQ2FHbHdiMlJJVW5kUGFUaDJZakpPZW1ORE5XaGpTRUp6V2xNMWFtSXlNSFppTWs1NlkwUkJla3hYUm5kalIzaHNZMjA1ZG1SSFRtaGFlazEzVG5kWlJGWlNNR1pDUkVGM1RHcEJjMjlEY1dkTFNWbHRZVWhTTUdORWIzWk1NazU1WWtNMWFHTklRbk5hVXpWcVlqSXdkbGxZUW5kaVIxWjVZakk1TUZreVJtNU5lVFZxWTIxM2QwaFJXVVJXVWpCUFFrSlpSVVpFT0hac1EwNVNNREZFU20xcFp6azNZa0k0TldNcmJHdEhTMXBOUVRSSFFURlZaRVIzUlVJdmQxRkZRWGRKUWtKcVFWRkNaMjl4YUd0cFJ6a3lUbXRDWjBsQ1FrRkpSa0ZFUVV0Q1oyZHhhR3RxVDFCUlVVUkJkMDV2UVVSQ2JFRnFRa0ZZYUZOeE5VbDVTMjluVFVOUWRIYzBPVEJDWVVJMk56ZERZVVZIU2xoMVpsRkNMMFZ4V2tka05rTlRhbWxEZEU5dWRVMVVZbGhXV0cxNGVHTjRabXREVFZGRVZGTlFlR0Z5V2xoMlRuSnJlRlV6Vkd0VlRVa3pNM2w2ZGtaV1ZsSlVOSGQ0VjBwRE9UazBUM05rWTFvMEsxSkhUbk5aUkhsU05XZHRaSEl3YmtSSFp6MGlMQ0pOU1VsRFVYcERRMEZqYldkQmQwbENRV2RKU1V4aldEaHBUa3hHVXpWVmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhkYWVrVmlUVUpyUjBFeFZVVkJkM2RUVVZoQ2QySkhWV2RWYlRsMlpFTkNSRkZUUVhSSlJXTjZUVk5aZDBwQldVUldVVkZNUkVJeFFtTklRbk5hVTBKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVlJOUWtWSFFURlZSVU5uZDB0UldFSjNZa2RWWjFOWE5XcE1ha1ZNVFVGclIwRXhWVVZDYUUxRFZsWk5kMGhvWTA1TlZGRjNUa1JOZDAxVVozaFBWRUV5VjJoalRrMTZhM2RPUkUxM1RWUm5lRTlVUVRKWGFrSnVUVkp6ZDBkUldVUldVVkZFUkVKS1FtTklRbk5hVTBKVFlqSTVNRWxGVGtKSlF6Qm5VbnBOZUVwcVFXdENaMDVXUWtGelRVaFZSbmRqUjNoc1NVVk9iR051VW5CYWJXeHFXVmhTY0dJeU5HZFJXRll3WVVjNWVXRllValZOVWsxM1JWRlpSRlpSVVV0RVFYQkNZMGhDYzFwVFFrcGliVTExVFZGemQwTlJXVVJXVVZGSFJYZEtWbFY2UWpKTlFrRkhRbmx4UjFOTk5EbEJaMFZIUWxOMVFrSkJRV2xCTWtsQlFrcHFjRXg2TVVGamNWUjBhM2xLZVdkU1RXTXpVa05XT0dOWGFsUnVTR05HUW1KYVJIVlhiVUpUY0ROYVNIUm1WR3BxVkhWNGVFVjBXQzh4U0RkWmVWbHNNMG8yV1ZKaVZIcENVRVZXYjBFdlZtaFpSRXRZTVVSNWVFNUNNR05VWkdSeFdHdzFaSFpOVm5wMFN6VXhOMGxFZGxsMVZsUmFXSEJ0YTA5c1JVdE5ZVTVEVFVWQmQwaFJXVVJXVWpCUFFrSlpSVVpNZFhjemNVWlpUVFJwWVhCSmNWb3pjalk1TmpZdllYbDVVM0pOUVRoSFFURlZaRVYzUlVJdmQxRkdUVUZOUWtGbU9IZEVaMWxFVmxJd1VFRlJTQzlDUVZGRVFXZEZSMDFCYjBkRFEzRkhVMDAwT1VKQlRVUkJNbWRCVFVkVlEwMVJRMFEyWTBoRlJtdzBZVmhVVVZreVpUTjJPVWQzVDBGRldreDFUaXQ1VW1oSVJrUXZNMjFsYjNsb2NHMTJUM2RuVUZWdVVGZFVlRzVUTkdGMEszRkplRlZEVFVjeGJXbG9SRXN4UVROVlZEZ3lUbEY2TmpCcGJVOXNUVEkzYW1Ka2IxaDBNbEZtZVVaTmJTdFphR2xrUkd0TVJqRjJURlZoWjAwMlFtZEVOVFpMZVV0QlBUMGlYWDAuZXlKMGNtRnVjMkZqZEdsdmJrbGtJam9pTWpBd01EQXdNVEF5Tnpjd01Ua3lPQ0lzSW05eWFXZHBibUZzVkhKaGJuTmhZM1JwYjI1SlpDSTZJakl3TURBd01ERXdNalE1T1RNeU9Ua2lMQ0ozWldKUGNtUmxja3hwYm1WSmRHVnRTV1FpT2lJeU1EQXdNREF3TVRFME1qQXlNVFF3SWl3aVluVnVaR3hsU1dRaU9pSmpiMjB1Ykc5cmFTMXdjbTlxWldOMExteHZhMmt0YldWemMyVnVaMlZ5SWl3aWNISnZaSFZqZEVsa0lqb2lZMjl0TG1kbGRITmxjM05wYjI0dWIzSm5MbkJ5YjE5emRXSWlMQ0p6ZFdKelkzSnBjSFJwYjI1SGNtOTFjRWxrWlc1MGFXWnBaWElpT2lJeU1UYzFNamd4TkNJc0luQjFjbU5vWVhObFJHRjBaU0k2TVRjMU9UY3lOemM1TURBd01Dd2liM0pwWjJsdVlXeFFkWEpqYUdGelpVUmhkR1VpT2pFM05Ua3pNREU0TXpNd01EQXNJbVY0Y0dseVpYTkVZWFJsSWpveE56VTVOekkzT1Rjd01EQXdMQ0p4ZFdGdWRHbDBlU0k2TVN3aWRIbHdaU0k2SWtGMWRHOHRVbVZ1WlhkaFlteGxJRk4xWW5OamNtbHdkR2x2YmlJc0ltbHVRWEJ3VDNkdVpYSnphR2x3Vkhsd1pTSTZJbEJWVWtOSVFWTkZSQ0lzSW5OcFoyNWxaRVJoZEdVaU9qRTNOVGszTWpjNE1qRTVOVElzSW1WdWRtbHliMjV0Wlc1MElqb2lVMkZ1WkdKdmVDSXNJblJ5WVc1ellXTjBhVzl1VW1WaGMyOXVJam9pVUZWU1EwaEJVMFVpTENKemRHOXlaV1p5YjI1MElqb2lRVlZUSWl3aWMzUnZjbVZtY205dWRFbGtJam9pTVRRek5EWXdJaXdpY0hKcFkyVWlPakU1T1RBc0ltTjFjbkpsYm1ONUlqb2lRVlZFSWl3aVlYQndWSEpoYm5OaFkzUnBiMjVKWkNJNklqY3dORGc1TnpRMk9Ua3dNek00TXpreE9TSjkucXhINUFCZlhiaVVuQ1FTZTlRbHdYTUxkYmhkRTFGSTEtMUlSdUtuWXB3MEVlbDFaNE5EckdGYXNULVRNYkFBRmE4ZTROQ09BdV9RZEtzUHR5Z2x1T2ciLCJzaWduZWRSZW5ld2FsSW5mbyI6ImV5SmhiR2NpT2lKRlV6STFOaUlzSW5nMVl5STZXeUpOU1VsRlRWUkRRMEUzWVdkQmQwbENRV2RKVVZJNFMwaDZaRzQxTlRSYUwxVnZjbUZrVG5nNWRIcEJTMEpuWjNGb2EycFBVRkZSUkVGNlFqRk5WVkYzVVdkWlJGWlJVVVJFUkhSQ1kwaENjMXBUUWxoaU0wcHpXa2hrY0ZwSFZXZFNSMVl5V2xkNGRtTkhWbmxKUmtwc1lrZEdNR0ZYT1hWamVVSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlV4TlFXdEhRVEZWUlVOM2QwTlNlbGw0UlhwQlVrSm5UbFpDUVc5TlEydEdkMk5IZUd4SlJXeDFXWGswZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOUWpSWVJGUkpNVTFFYTNoUFZFVTFUa1JSTVUxV2IxaEVWRWt6VFZSQmVFMTZSVE5PUkdONVRURnZkMmRhU1hoUlJFRXJRbWRPVmtKQlRVMU9NVUo1WWpKUloxSlZUa1JKUlRGb1dYbENRbU5JUVdkVk0xSjJZMjFWWjFsWE5XdEpSMnhWWkZjMWJHTjVRbFJrUnpsNVdsTkNVMXBYVG14aFdFSXdTVVpPY0ZveU5YQmliV040VEVSQmNVSm5UbFpDUVhOTlNUQkdkMk5IZUd4SlJtUjJZMjE0YTJReWJHdGFVMEpGV2xoYWJHSkhPWGRhV0VsblZXMVdjMWxZVW5CaU1qVjZUVkpOZDBWUldVUldVVkZMUkVGd1FtTklRbk5hVTBKS1ltMU5kVTFSYzNkRFVWbEVWbEZSUjBWM1NsWlZla0phVFVKTlIwSjVjVWRUVFRRNVFXZEZSME5EY1VkVFRUUTVRWGRGU0VFd1NVRkNUbTVXZG1oamRqZHBWQ3MzUlhnMWRFSk5RbWR5VVhOd1NIcEpjMWhTYVRCWmVHWmxhemRzZGpoM1JXMXFMMkpJYVZkMFRuZEtjV015UW05SWVuTlJhVVZxVURkTFJrbEpTMmMwV1RoNU1DOXVlVzUxUVcxcVoyZEpTVTFKU1VOQ1JFRk5RbWRPVmtoU1RVSkJaamhGUVdwQlFVMUNPRWRCTVZWa1NYZFJXVTFDWVVGR1JEaDJiRU5PVWpBeFJFcHRhV2M1TjJKQ09EVmpLMnhyUjB0YVRVaEJSME5EYzBkQlVWVkdRbmRGUWtKSFVYZFpha0YwUW1kbmNrSm5SVVpDVVdOM1FXOVphR0ZJVWpCalJHOTJUREpPYkdOdVVucE1iVVozWTBkNGJFeHRUblppVXprelpESlNlVnA2V1hWYVIxWjVUVVJGUjBORGMwZEJVVlZHUW5wQlFtaHBWbTlrU0ZKM1QyazRkbUl5VG5walF6Vm9ZMGhDYzFwVE5XcGlNakIyWWpKT2VtTkVRWHBNV0dReldraEtiazVxUVhsTlNVbENTR2RaUkZaU01HZENTVWxDUmxSRFEwRlNSWGRuWjBWT1FtZHZjV2hyYVVjNU1rNXJRbEZaUWsxSlNDdE5TVWhFUW1kbmNrSm5SVVpDVVdORFFXcERRblJuZVVKek1VcHNZa2RzYUdKdFRteEpSemwxU1VoU2IyRllUV2RaTWxaNVpFZHNiV0ZYVG1oa1IxVm5XVzVyWjFsWE5UVkpTRUpvWTI1U05VbEhSbnBqTTFaMFdsaE5aMWxYVG1wYVdFSXdXVmMxYWxwVFFuWmFhVUl3WVVkVloyUkhhR3hpYVVKb1kwaENjMkZYVG1oWmJYaHNTVWhPTUZsWE5XdFpXRXByU1VoU2JHTnRNWHBKUjBaMVdrTkNhbUl5Tld0aFdGSndZakkxZWtsSE9XMUpTRlo2V2xOM1oxa3lWbmxrUjJ4dFlWZE9hR1JIVldkalJ6bHpZVmRPTlVsSFJuVmFRMEpxV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxJUW5sWlYwNHdZVmRPYkVsSVRqQlpXRkpzWWxkV2RXUklUWFZOUkZsSFEwTnpSMEZSVlVaQ2QwbENSbWx3YjJSSVVuZFBhVGgyWkROa00weHRSbmRqUjNoc1RHMU9kbUpUT1dwYVdFb3dZVmRhY0ZreVJqQmFWMFl4WkVkb2RtTnRiREJsVXpoM1NGRlpSRlpTTUU5Q1FsbEZSa2xHYVc5SE5IZE5UVlpCTVd0MU9YcEtiVWRPVUVGV2JqTmxjVTFCTkVkQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlVVSm5iM0ZvYTJsSE9USk9hMEpuYzBKQ1FVbEdRVVJCUzBKblozRm9hMnBQVUZGUlJFRjNUbkJCUkVKdFFXcEZRU3R4V0c1U1JVTTNhRmhKVjFaTWMweDRlbTVxVW5CSmVsQm1OMVpJZWpsV0wwTlViVGdyVEVwc2NsRmxjRzV0WTFCMlIweE9ZMWcyV0ZCdWJHTm5URUZCYWtWQk5VbHFUbHBMWjJjMWNGRTNPV3R1UmpSSllsUllaRXQyT0haMWRFbEVUVmhFYldwUVZsUXpaRWQyUm5SelIxSjNXRTk1ZDFJeWExcERaRk55Wm1WdmRDSXNJazFKU1VSR2FrTkRRWEI1WjBGM1NVSkJaMGxWU1hOSGFGSjNjREJqTW01MlZUUlpVM2xqWVdaUVZHcDZZazVqZDBObldVbExiMXBKZW1vd1JVRjNUWGRhZWtWaVRVSnJSMEV4VlVWQmQzZFRVVmhDZDJKSFZXZFZiVGwyWkVOQ1JGRlRRWFJKUldONlRWTlpkMHBCV1VSV1VWRk1SRUl4UW1OSVFuTmFVMEpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJWUk5Ra1ZIUVRGVlJVTm5kMHRSV0VKM1lrZFZaMU5YTldwTWFrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmQwaG9ZMDVOYWtWM1RYcEZNMDFxUVhwT2VrVjNWMmhqVGsxNldYZE5la1UxVFVSQmQwMUVRWGRYYWtJeFRWVlJkMUZuV1VSV1VWRkVSRVIwUW1OSVFuTmFVMEpZWWpOS2MxcElaSEJhUjFWblVrZFdNbHBYZUhaalIxWjVTVVpLYkdKSFJqQmhWemwxWTNsQ1JGcFlTakJoVjFwd1dUSkdNR0ZYT1hWSlJVWXhaRWRvZG1OdGJEQmxWRVZNVFVGclIwRXhWVVZEZDNkRFVucFplRVY2UVZKQ1owNVdRa0Z2VFVOclJuZGpSM2hzU1VWc2RWbDVOSGhEZWtGS1FtZE9Wa0pCV1ZSQmJGWlVUVWhaZDBWQldVaExiMXBKZW1vd1EwRlJXVVpMTkVWRlFVTkpSRmxuUVVWaWMxRkxRemswVUhKc1YyMWFXRzVZWjNSNGVtUldTa3c0VkRCVFIxbHVaMFJTUjNCdVoyNHpUalpRVkRoS1RVVmlOMFpFYVRSaVFtMVFhRU51V2pNdmMzRTJVRVl2WTBkalMxaFhjMHcxZGs5MFpWSm9lVW8wTlhnelFWTlFOMk5QUWl0aFlXODVNR1pqY0hoVGRpOUZXa1ppYm1sQllrNW5Xa2RvU1dod1NXODBTRFpOU1VnelRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaamhEUVZGQmQwaDNXVVJXVWpCcVFrSm5kMFp2UVZWMU4wUmxiMVpuZW1sS2NXdHBjRzVsZG5JemNuSTVja3hLUzNOM1VtZFpTVXQzV1VKQ1VWVklRVkZGUlU5cVFUUk5SRmxIUTBOelIwRlJWVVpDZWtGQ2FHbHdiMlJJVW5kUGFUaDJZakpPZW1ORE5XaGpTRUp6V2xNMWFtSXlNSFppTWs1NlkwUkJla3hYUm5kalIzaHNZMjA1ZG1SSFRtaGFlazEzVG5kWlJGWlNNR1pDUkVGM1RHcEJjMjlEY1dkTFNWbHRZVWhTTUdORWIzWk1NazU1WWtNMWFHTklRbk5hVXpWcVlqSXdkbGxZUW5kaVIxWjVZakk1TUZreVJtNU5lVFZxWTIxM2QwaFJXVVJXVWpCUFFrSlpSVVpFT0hac1EwNVNNREZFU20xcFp6azNZa0k0TldNcmJHdEhTMXBOUVRSSFFURlZaRVIzUlVJdmQxRkZRWGRKUWtKcVFWRkNaMjl4YUd0cFJ6a3lUbXRDWjBsQ1FrRkpSa0ZFUVV0Q1oyZHhhR3RxVDFCUlVVUkJkMDV2UVVSQ2JFRnFRa0ZZYUZOeE5VbDVTMjluVFVOUWRIYzBPVEJDWVVJMk56ZERZVVZIU2xoMVpsRkNMMFZ4V2tka05rTlRhbWxEZEU5dWRVMVVZbGhXV0cxNGVHTjRabXREVFZGRVZGTlFlR0Z5V2xoMlRuSnJlRlV6Vkd0VlRVa3pNM2w2ZGtaV1ZsSlVOSGQ0VjBwRE9UazBUM05rWTFvMEsxSkhUbk5aUkhsU05XZHRaSEl3YmtSSFp6MGlMQ0pOU1VsRFVYcERRMEZqYldkQmQwbENRV2RKU1V4aldEaHBUa3hHVXpWVmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhkYWVrVmlUVUpyUjBFeFZVVkJkM2RUVVZoQ2QySkhWV2RWYlRsMlpFTkNSRkZUUVhSSlJXTjZUVk5aZDBwQldVUldVVkZNUkVJeFFtTklRbk5hVTBKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVlJOUWtWSFFURlZSVU5uZDB0UldFSjNZa2RWWjFOWE5XcE1ha1ZNVFVGclIwRXhWVVZDYUUxRFZsWk5kMGhvWTA1TlZGRjNUa1JOZDAxVVozaFBWRUV5VjJoalRrMTZhM2RPUkUxM1RWUm5lRTlVUVRKWGFrSnVUVkp6ZDBkUldVUldVVkZFUkVKS1FtTklRbk5hVTBKVFlqSTVNRWxGVGtKSlF6Qm5VbnBOZUVwcVFXdENaMDVXUWtGelRVaFZSbmRqUjNoc1NVVk9iR051VW5CYWJXeHFXVmhTY0dJeU5HZFJXRll3WVVjNWVXRllValZOVWsxM1JWRlpSRlpSVVV0RVFYQkNZMGhDYzFwVFFrcGliVTExVFZGemQwTlJXVVJXVVZGSFJYZEtWbFY2UWpKTlFrRkhRbmx4UjFOTk5EbEJaMFZIUWxOMVFrSkJRV2xCTWtsQlFrcHFjRXg2TVVGamNWUjBhM2xLZVdkU1RXTXpVa05XT0dOWGFsUnVTR05HUW1KYVJIVlhiVUpUY0ROYVNIUm1WR3BxVkhWNGVFVjBXQzh4U0RkWmVWbHNNMG8yV1ZKaVZIcENVRVZXYjBFdlZtaFpSRXRZTVVSNWVFNUNNR05VWkdSeFdHdzFaSFpOVm5wMFN6VXhOMGxFZGxsMVZsUmFXSEJ0YTA5c1JVdE5ZVTVEVFVWQmQwaFJXVVJXVWpCUFFrSlpSVVpNZFhjemNVWlpUVFJwWVhCSmNWb3pjalk1TmpZdllYbDVVM0pOUVRoSFFURlZaRVYzUlVJdmQxRkdUVUZOUWtGbU9IZEVaMWxFVmxJd1VFRlJTQzlDUVZGRVFXZEZSMDFCYjBkRFEzRkhVMDAwT1VKQlRVUkJNbWRCVFVkVlEwMVJRMFEyWTBoRlJtdzBZVmhVVVZreVpUTjJPVWQzVDBGRldreDFUaXQ1VW1oSVJrUXZNMjFsYjNsb2NHMTJUM2RuVUZWdVVGZFVlRzVUTkdGMEszRkplRlZEVFVjeGJXbG9SRXN4UVROVlZEZ3lUbEY2TmpCcGJVOXNUVEkzYW1Ka2IxaDBNbEZtZVVaTmJTdFphR2xrUkd0TVJqRjJURlZoWjAwMlFtZEVOVFpMZVV0QlBUMGlYWDAuZXlKdmNtbG5hVzVoYkZSeVlXNXpZV04wYVc5dVNXUWlPaUl5TURBd01EQXhNREkwT1Rrek1qazVJaXdpWVhWMGIxSmxibVYzVUhKdlpIVmpkRWxrSWpvaVkyOXRMbWRsZEhObGMzTnBiMjR1YjNKbkxuQnliMTl6ZFdJaUxDSndjbTlrZFdOMFNXUWlPaUpqYjIwdVoyVjBjMlZ6YzJsdmJpNXZjbWN1Y0hKdlgzTjFZaUlzSW1GMWRHOVNaVzVsZDFOMFlYUjFjeUk2TUN3aWMybG5ibVZrUkdGMFpTSTZNVGMxT1RjeU56Z3lNVGsxTWl3aVpXNTJhWEp2Ym0xbGJuUWlPaUpUWVc1a1ltOTRJaXdpY21WalpXNTBVM1ZpYzJOeWFYQjBhVzl1VTNSaGNuUkVZWFJsSWpveE56VTVOekkzTnpjNE1EQXdMQ0p5Wlc1bGQyRnNSR0YwWlNJNk1UYzFPVGN5TnprM01EQXdNQ3dpWVhCd1ZISmhibk5oWTNScGIyNUpaQ0k2SWpjd05EZzVOelEyT1Rrd016TTRNemt4T1NKOS5mUjdLa2RSZm1jdFNjOFZZSnNHTE5ObnF0b1htSGdtdmFpbkQtNEwwXzVpVkJEUWxraVRHWXR1b0g0bHlpd1pZOThYOFBPZHFpVS1nZGhYRGZ2M3BMUSIsInN0YXR1cyI6MX0sInZlcnNpb24iOiIyLjAiLCJzaWduZWREYXRlIjoxNzU5NzI3ODIxOTUyfQ.gIm-WGnIiDwgenNrPhlcsJB6V0Jq_q0Ky-KxPz2oSvNukdkl1hK4wzQONW61_0Rzcm90NekWIWBNimPj2iVbSA"
            }
            ''')

            e03_queue_downgrade_to_3_months: dict[str, base.JSONValue] = json.loads('''
            {
            "signedPayload": "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJub3RpZmljYXRpb25UeXBlIjoiRElEX0NIQU5HRV9SRU5FV0FMX1BSRUYiLCJzdWJ0eXBlIjoiRE9XTkdSQURFIiwibm90aWZpY2F0aW9uVVVJRCI6IjAxYzU3NGRjLTY0YjctNDVkMy04ODlhLTVmZGNiMDhmYjVjMCIsImRhdGEiOnsiYXBwQXBwbGVJZCI6MTQ3MDE2ODg2OCwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwiYnVuZGxlVmVyc2lvbiI6IjYzNyIsImVudmlyb25tZW50IjoiU2FuZGJveCIsInNpZ25lZFRyYW5zYWN0aW9uSW5mbyI6ImV5SmhiR2NpT2lKRlV6STFOaUlzSW5nMVl5STZXeUpOU1VsRlRWUkRRMEUzWVdkQmQwbENRV2RKVVZJNFMwaDZaRzQxTlRSYUwxVnZjbUZrVG5nNWRIcEJTMEpuWjNGb2EycFBVRkZSUkVGNlFqRk5WVkYzVVdkWlJGWlJVVVJFUkhSQ1kwaENjMXBUUWxoaU0wcHpXa2hrY0ZwSFZXZFNSMVl5V2xkNGRtTkhWbmxKUmtwc1lrZEdNR0ZYT1hWamVVSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlV4TlFXdEhRVEZWUlVOM2QwTlNlbGw0UlhwQlVrSm5UbFpDUVc5TlEydEdkMk5IZUd4SlJXeDFXWGswZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOUWpSWVJGUkpNVTFFYTNoUFZFVTFUa1JSTVUxV2IxaEVWRWt6VFZSQmVFMTZSVE5PUkdONVRURnZkMmRhU1hoUlJFRXJRbWRPVmtKQlRVMU9NVUo1WWpKUloxSlZUa1JKUlRGb1dYbENRbU5JUVdkVk0xSjJZMjFWWjFsWE5XdEpSMnhWWkZjMWJHTjVRbFJrUnpsNVdsTkNVMXBYVG14aFdFSXdTVVpPY0ZveU5YQmliV040VEVSQmNVSm5UbFpDUVhOTlNUQkdkMk5IZUd4SlJtUjJZMjE0YTJReWJHdGFVMEpGV2xoYWJHSkhPWGRhV0VsblZXMVdjMWxZVW5CaU1qVjZUVkpOZDBWUldVUldVVkZMUkVGd1FtTklRbk5hVTBKS1ltMU5kVTFSYzNkRFVWbEVWbEZSUjBWM1NsWlZla0phVFVKTlIwSjVjVWRUVFRRNVFXZEZSME5EY1VkVFRUUTVRWGRGU0VFd1NVRkNUbTVXZG1oamRqZHBWQ3MzUlhnMWRFSk5RbWR5VVhOd1NIcEpjMWhTYVRCWmVHWmxhemRzZGpoM1JXMXFMMkpJYVZkMFRuZEtjV015UW05SWVuTlJhVVZxVURkTFJrbEpTMmMwV1RoNU1DOXVlVzUxUVcxcVoyZEpTVTFKU1VOQ1JFRk5RbWRPVmtoU1RVSkJaamhGUVdwQlFVMUNPRWRCTVZWa1NYZFJXVTFDWVVGR1JEaDJiRU5PVWpBeFJFcHRhV2M1TjJKQ09EVmpLMnhyUjB0YVRVaEJSME5EYzBkQlVWVkdRbmRGUWtKSFVYZFpha0YwUW1kbmNrSm5SVVpDVVdOM1FXOVphR0ZJVWpCalJHOTJUREpPYkdOdVVucE1iVVozWTBkNGJFeHRUblppVXprelpESlNlVnA2V1hWYVIxWjVUVVJGUjBORGMwZEJVVlZHUW5wQlFtaHBWbTlrU0ZKM1QyazRkbUl5VG5walF6Vm9ZMGhDYzFwVE5XcGlNakIyWWpKT2VtTkVRWHBNV0dReldraEtiazVxUVhsTlNVbENTR2RaUkZaU01HZENTVWxDUmxSRFEwRlNSWGRuWjBWT1FtZHZjV2hyYVVjNU1rNXJRbEZaUWsxSlNDdE5TVWhFUW1kbmNrSm5SVVpDVVdORFFXcERRblJuZVVKek1VcHNZa2RzYUdKdFRteEpSemwxU1VoU2IyRllUV2RaTWxaNVpFZHNiV0ZYVG1oa1IxVm5XVzVyWjFsWE5UVkpTRUpvWTI1U05VbEhSbnBqTTFaMFdsaE5aMWxYVG1wYVdFSXdXVmMxYWxwVFFuWmFhVUl3WVVkVloyUkhhR3hpYVVKb1kwaENjMkZYVG1oWmJYaHNTVWhPTUZsWE5XdFpXRXByU1VoU2JHTnRNWHBKUjBaMVdrTkNhbUl5Tld0aFdGSndZakkxZWtsSE9XMUpTRlo2V2xOM1oxa3lWbmxrUjJ4dFlWZE9hR1JIVldkalJ6bHpZVmRPTlVsSFJuVmFRMEpxV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxJUW5sWlYwNHdZVmRPYkVsSVRqQlpXRkpzWWxkV2RXUklUWFZOUkZsSFEwTnpSMEZSVlVaQ2QwbENSbWx3YjJSSVVuZFBhVGgyWkROa00weHRSbmRqUjNoc1RHMU9kbUpUT1dwYVdFb3dZVmRhY0ZreVJqQmFWMFl4WkVkb2RtTnRiREJsVXpoM1NGRlpSRlpTTUU5Q1FsbEZSa2xHYVc5SE5IZE5UVlpCTVd0MU9YcEtiVWRPVUVGV2JqTmxjVTFCTkVkQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlVVSm5iM0ZvYTJsSE9USk9hMEpuYzBKQ1FVbEdRVVJCUzBKblozRm9hMnBQVUZGUlJFRjNUbkJCUkVKdFFXcEZRU3R4V0c1U1JVTTNhRmhKVjFaTWMweDRlbTVxVW5CSmVsQm1OMVpJZWpsV0wwTlViVGdyVEVwc2NsRmxjRzV0WTFCMlIweE9ZMWcyV0ZCdWJHTm5URUZCYWtWQk5VbHFUbHBMWjJjMWNGRTNPV3R1UmpSSllsUllaRXQyT0haMWRFbEVUVmhFYldwUVZsUXpaRWQyUm5SelIxSjNXRTk1ZDFJeWExcERaRk55Wm1WdmRDSXNJazFKU1VSR2FrTkRRWEI1WjBGM1NVSkJaMGxWU1hOSGFGSjNjREJqTW01MlZUUlpVM2xqWVdaUVZHcDZZazVqZDBObldVbExiMXBKZW1vd1JVRjNUWGRhZWtWaVRVSnJSMEV4VlVWQmQzZFRVVmhDZDJKSFZXZFZiVGwyWkVOQ1JGRlRRWFJKUldONlRWTlpkMHBCV1VSV1VWRk1SRUl4UW1OSVFuTmFVMEpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJWUk5Ra1ZIUVRGVlJVTm5kMHRSV0VKM1lrZFZaMU5YTldwTWFrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmQwaG9ZMDVOYWtWM1RYcEZNMDFxUVhwT2VrVjNWMmhqVGsxNldYZE5la1UxVFVSQmQwMUVRWGRYYWtJeFRWVlJkMUZuV1VSV1VWRkVSRVIwUW1OSVFuTmFVMEpZWWpOS2MxcElaSEJhUjFWblVrZFdNbHBYZUhaalIxWjVTVVpLYkdKSFJqQmhWemwxWTNsQ1JGcFlTakJoVjFwd1dUSkdNR0ZYT1hWSlJVWXhaRWRvZG1OdGJEQmxWRVZNVFVGclIwRXhWVVZEZDNkRFVucFplRVY2UVZKQ1owNVdRa0Z2VFVOclJuZGpSM2hzU1VWc2RWbDVOSGhEZWtGS1FtZE9Wa0pCV1ZSQmJGWlVUVWhaZDBWQldVaExiMXBKZW1vd1EwRlJXVVpMTkVWRlFVTkpSRmxuUVVWaWMxRkxRemswVUhKc1YyMWFXRzVZWjNSNGVtUldTa3c0VkRCVFIxbHVaMFJTUjNCdVoyNHpUalpRVkRoS1RVVmlOMFpFYVRSaVFtMVFhRU51V2pNdmMzRTJVRVl2WTBkalMxaFhjMHcxZGs5MFpWSm9lVW8wTlhnelFWTlFOMk5QUWl0aFlXODVNR1pqY0hoVGRpOUZXa1ppYm1sQllrNW5Xa2RvU1dod1NXODBTRFpOU1VnelRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaamhEUVZGQmQwaDNXVVJXVWpCcVFrSm5kMFp2UVZWMU4wUmxiMVpuZW1sS2NXdHBjRzVsZG5JemNuSTVja3hLUzNOM1VtZFpTVXQzV1VKQ1VWVklRVkZGUlU5cVFUUk5SRmxIUTBOelIwRlJWVVpDZWtGQ2FHbHdiMlJJVW5kUGFUaDJZakpPZW1ORE5XaGpTRUp6V2xNMWFtSXlNSFppTWs1NlkwUkJla3hYUm5kalIzaHNZMjA1ZG1SSFRtaGFlazEzVG5kWlJGWlNNR1pDUkVGM1RHcEJjMjlEY1dkTFNWbHRZVWhTTUdORWIzWk1NazU1WWtNMWFHTklRbk5hVXpWcVlqSXdkbGxZUW5kaVIxWjVZakk1TUZreVJtNU5lVFZxWTIxM2QwaFJXVVJXVWpCUFFrSlpSVVpFT0hac1EwNVNNREZFU20xcFp6azNZa0k0TldNcmJHdEhTMXBOUVRSSFFURlZaRVIzUlVJdmQxRkZRWGRKUWtKcVFWRkNaMjl4YUd0cFJ6a3lUbXRDWjBsQ1FrRkpSa0ZFUVV0Q1oyZHhhR3RxVDFCUlVVUkJkMDV2UVVSQ2JFRnFRa0ZZYUZOeE5VbDVTMjluVFVOUWRIYzBPVEJDWVVJMk56ZERZVVZIU2xoMVpsRkNMMFZ4V2tka05rTlRhbWxEZEU5dWRVMVVZbGhXV0cxNGVHTjRabXREVFZGRVZGTlFlR0Z5V2xoMlRuSnJlRlV6Vkd0VlRVa3pNM2w2ZGtaV1ZsSlVOSGQ0VjBwRE9UazBUM05rWTFvMEsxSkhUbk5aUkhsU05XZHRaSEl3YmtSSFp6MGlMQ0pOU1VsRFVYcERRMEZqYldkQmQwbENRV2RKU1V4aldEaHBUa3hHVXpWVmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhkYWVrVmlUVUpyUjBFeFZVVkJkM2RUVVZoQ2QySkhWV2RWYlRsMlpFTkNSRkZUUVhSSlJXTjZUVk5aZDBwQldVUldVVkZNUkVJeFFtTklRbk5hVTBKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVlJOUWtWSFFURlZSVU5uZDB0UldFSjNZa2RWWjFOWE5XcE1ha1ZNVFVGclIwRXhWVVZDYUUxRFZsWk5kMGhvWTA1TlZGRjNUa1JOZDAxVVozaFBWRUV5VjJoalRrMTZhM2RPUkUxM1RWUm5lRTlVUVRKWGFrSnVUVkp6ZDBkUldVUldVVkZFUkVKS1FtTklRbk5hVTBKVFlqSTVNRWxGVGtKSlF6Qm5VbnBOZUVwcVFXdENaMDVXUWtGelRVaFZSbmRqUjNoc1NVVk9iR051VW5CYWJXeHFXVmhTY0dJeU5HZFJXRll3WVVjNWVXRllValZOVWsxM1JWRlpSRlpSVVV0RVFYQkNZMGhDYzFwVFFrcGliVTExVFZGemQwTlJXVVJXVVZGSFJYZEtWbFY2UWpKTlFrRkhRbmx4UjFOTk5EbEJaMFZIUWxOMVFrSkJRV2xCTWtsQlFrcHFjRXg2TVVGamNWUjBhM2xLZVdkU1RXTXpVa05XT0dOWGFsUnVTR05HUW1KYVJIVlhiVUpUY0ROYVNIUm1WR3BxVkhWNGVFVjBXQzh4U0RkWmVWbHNNMG8yV1ZKaVZIcENVRVZXYjBFdlZtaFpSRXRZTVVSNWVFNUNNR05VWkdSeFdHdzFaSFpOVm5wMFN6VXhOMGxFZGxsMVZsUmFXSEJ0YTA5c1JVdE5ZVTVEVFVWQmQwaFJXVVJXVWpCUFFrSlpSVVpNZFhjemNVWlpUVFJwWVhCSmNWb3pjalk1TmpZdllYbDVVM0pOUVRoSFFURlZaRVYzUlVJdmQxRkdUVUZOUWtGbU9IZEVaMWxFVmxJd1VFRlJTQzlDUVZGRVFXZEZSMDFCYjBkRFEzRkhVMDAwT1VKQlRVUkJNbWRCVFVkVlEwMVJRMFEyWTBoRlJtdzBZVmhVVVZreVpUTjJPVWQzVDBGRldreDFUaXQ1VW1oSVJrUXZNMjFsYjNsb2NHMTJUM2RuVUZWdVVGZFVlRzVUTkdGMEszRkplRlZEVFVjeGJXbG9SRXN4UVROVlZEZ3lUbEY2TmpCcGJVOXNUVEkzYW1Ka2IxaDBNbEZtZVVaTmJTdFphR2xrUkd0TVJqRjJURlZoWjAwMlFtZEVOVFpMZVV0QlBUMGlYWDAuZXlKMGNtRnVjMkZqZEdsdmJrbGtJam9pTWpBd01EQXdNVEF5Tnpjd01Ua3lPQ0lzSW05eWFXZHBibUZzVkhKaGJuTmhZM1JwYjI1SlpDSTZJakl3TURBd01ERXdNalE1T1RNeU9Ua2lMQ0ozWldKUGNtUmxja3hwYm1WSmRHVnRTV1FpT2lJeU1EQXdNREF3TVRFME1qQXlNVFF3SWl3aVluVnVaR3hsU1dRaU9pSmpiMjB1Ykc5cmFTMXdjbTlxWldOMExteHZhMmt0YldWemMyVnVaMlZ5SWl3aWNISnZaSFZqZEVsa0lqb2lZMjl0TG1kbGRITmxjM05wYjI0dWIzSm5MbkJ5YjE5emRXSWlMQ0p6ZFdKelkzSnBjSFJwYjI1SGNtOTFjRWxrWlc1MGFXWnBaWElpT2lJeU1UYzFNamd4TkNJc0luQjFjbU5vWVhObFJHRjBaU0k2TVRjMU9UY3lOemM1TURBd01Dd2liM0pwWjJsdVlXeFFkWEpqYUdGelpVUmhkR1VpT2pFM05Ua3pNREU0TXpNd01EQXNJbVY0Y0dseVpYTkVZWFJsSWpveE56VTVOekkzT1Rjd01EQXdMQ0p4ZFdGdWRHbDBlU0k2TVN3aWRIbHdaU0k2SWtGMWRHOHRVbVZ1WlhkaFlteGxJRk4xWW5OamNtbHdkR2x2YmlJc0ltbHVRWEJ3VDNkdVpYSnphR2x3Vkhsd1pTSTZJbEJWVWtOSVFWTkZSQ0lzSW5OcFoyNWxaRVJoZEdVaU9qRTNOVGszTWpjNE16ZzBOVEFzSW1WdWRtbHliMjV0Wlc1MElqb2lVMkZ1WkdKdmVDSXNJblJ5WVc1ellXTjBhVzl1VW1WaGMyOXVJam9pVUZWU1EwaEJVMFVpTENKemRHOXlaV1p5YjI1MElqb2lRVlZUSWl3aWMzUnZjbVZtY205dWRFbGtJam9pTVRRek5EWXdJaXdpY0hKcFkyVWlPakU1T1RBc0ltTjFjbkpsYm1ONUlqb2lRVlZFSWl3aVlYQndWSEpoYm5OaFkzUnBiMjVKWkNJNklqY3dORGc1TnpRMk9Ua3dNek00TXpreE9TSjkuQ2pMM1hlUWZLUWF6LWJDd3JZc0RHbFZLVEhnb2VnMXpYWHNoZUd0c3VNc3F6eEpyakY3VmR1dHN5d1lfWXlRN2x6V2lPdUVCNG5xWFg5Nlp2SnBKaUEiLCJzaWduZWRSZW5ld2FsSW5mbyI6ImV5SmhiR2NpT2lKRlV6STFOaUlzSW5nMVl5STZXeUpOU1VsRlRWUkRRMEUzWVdkQmQwbENRV2RKVVZJNFMwaDZaRzQxTlRSYUwxVnZjbUZrVG5nNWRIcEJTMEpuWjNGb2EycFBVRkZSUkVGNlFqRk5WVkYzVVdkWlJGWlJVVVJFUkhSQ1kwaENjMXBUUWxoaU0wcHpXa2hrY0ZwSFZXZFNSMVl5V2xkNGRtTkhWbmxKUmtwc1lrZEdNR0ZYT1hWamVVSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlV4TlFXdEhRVEZWUlVOM2QwTlNlbGw0UlhwQlVrSm5UbFpDUVc5TlEydEdkMk5IZUd4SlJXeDFXWGswZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOUWpSWVJGUkpNVTFFYTNoUFZFVTFUa1JSTVUxV2IxaEVWRWt6VFZSQmVFMTZSVE5PUkdONVRURnZkMmRhU1hoUlJFRXJRbWRPVmtKQlRVMU9NVUo1WWpKUloxSlZUa1JKUlRGb1dYbENRbU5JUVdkVk0xSjJZMjFWWjFsWE5XdEpSMnhWWkZjMWJHTjVRbFJrUnpsNVdsTkNVMXBYVG14aFdFSXdTVVpPY0ZveU5YQmliV040VEVSQmNVSm5UbFpDUVhOTlNUQkdkMk5IZUd4SlJtUjJZMjE0YTJReWJHdGFVMEpGV2xoYWJHSkhPWGRhV0VsblZXMVdjMWxZVW5CaU1qVjZUVkpOZDBWUldVUldVVkZMUkVGd1FtTklRbk5hVTBKS1ltMU5kVTFSYzNkRFVWbEVWbEZSUjBWM1NsWlZla0phVFVKTlIwSjVjVWRUVFRRNVFXZEZSME5EY1VkVFRUUTVRWGRGU0VFd1NVRkNUbTVXZG1oamRqZHBWQ3MzUlhnMWRFSk5RbWR5VVhOd1NIcEpjMWhTYVRCWmVHWmxhemRzZGpoM1JXMXFMMkpJYVZkMFRuZEtjV015UW05SWVuTlJhVVZxVURkTFJrbEpTMmMwV1RoNU1DOXVlVzUxUVcxcVoyZEpTVTFKU1VOQ1JFRk5RbWRPVmtoU1RVSkJaamhGUVdwQlFVMUNPRWRCTVZWa1NYZFJXVTFDWVVGR1JEaDJiRU5PVWpBeFJFcHRhV2M1TjJKQ09EVmpLMnhyUjB0YVRVaEJSME5EYzBkQlVWVkdRbmRGUWtKSFVYZFpha0YwUW1kbmNrSm5SVVpDVVdOM1FXOVphR0ZJVWpCalJHOTJUREpPYkdOdVVucE1iVVozWTBkNGJFeHRUblppVXprelpESlNlVnA2V1hWYVIxWjVUVVJGUjBORGMwZEJVVlZHUW5wQlFtaHBWbTlrU0ZKM1QyazRkbUl5VG5walF6Vm9ZMGhDYzFwVE5XcGlNakIyWWpKT2VtTkVRWHBNV0dReldraEtiazVxUVhsTlNVbENTR2RaUkZaU01HZENTVWxDUmxSRFEwRlNSWGRuWjBWT1FtZHZjV2hyYVVjNU1rNXJRbEZaUWsxSlNDdE5TVWhFUW1kbmNrSm5SVVpDVVdORFFXcERRblJuZVVKek1VcHNZa2RzYUdKdFRteEpSemwxU1VoU2IyRllUV2RaTWxaNVpFZHNiV0ZYVG1oa1IxVm5XVzVyWjFsWE5UVkpTRUpvWTI1U05VbEhSbnBqTTFaMFdsaE5aMWxYVG1wYVdFSXdXVmMxYWxwVFFuWmFhVUl3WVVkVloyUkhhR3hpYVVKb1kwaENjMkZYVG1oWmJYaHNTVWhPTUZsWE5XdFpXRXByU1VoU2JHTnRNWHBKUjBaMVdrTkNhbUl5Tld0aFdGSndZakkxZWtsSE9XMUpTRlo2V2xOM1oxa3lWbmxrUjJ4dFlWZE9hR1JIVldkalJ6bHpZVmRPTlVsSFJuVmFRMEpxV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxJUW5sWlYwNHdZVmRPYkVsSVRqQlpXRkpzWWxkV2RXUklUWFZOUkZsSFEwTnpSMEZSVlVaQ2QwbENSbWx3YjJSSVVuZFBhVGgyWkROa00weHRSbmRqUjNoc1RHMU9kbUpUT1dwYVdFb3dZVmRhY0ZreVJqQmFWMFl4WkVkb2RtTnRiREJsVXpoM1NGRlpSRlpTTUU5Q1FsbEZSa2xHYVc5SE5IZE5UVlpCTVd0MU9YcEtiVWRPVUVGV2JqTmxjVTFCTkVkQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlVVSm5iM0ZvYTJsSE9USk9hMEpuYzBKQ1FVbEdRVVJCUzBKblozRm9hMnBQVUZGUlJFRjNUbkJCUkVKdFFXcEZRU3R4V0c1U1JVTTNhRmhKVjFaTWMweDRlbTVxVW5CSmVsQm1OMVpJZWpsV0wwTlViVGdyVEVwc2NsRmxjRzV0WTFCMlIweE9ZMWcyV0ZCdWJHTm5URUZCYWtWQk5VbHFUbHBMWjJjMWNGRTNPV3R1UmpSSllsUllaRXQyT0haMWRFbEVUVmhFYldwUVZsUXpaRWQyUm5SelIxSjNXRTk1ZDFJeWExcERaRk55Wm1WdmRDSXNJazFKU1VSR2FrTkRRWEI1WjBGM1NVSkJaMGxWU1hOSGFGSjNjREJqTW01MlZUUlpVM2xqWVdaUVZHcDZZazVqZDBObldVbExiMXBKZW1vd1JVRjNUWGRhZWtWaVRVSnJSMEV4VlVWQmQzZFRVVmhDZDJKSFZXZFZiVGwyWkVOQ1JGRlRRWFJKUldONlRWTlpkMHBCV1VSV1VWRk1SRUl4UW1OSVFuTmFVMEpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJWUk5Ra1ZIUVRGVlJVTm5kMHRSV0VKM1lrZFZaMU5YTldwTWFrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmQwaG9ZMDVOYWtWM1RYcEZNMDFxUVhwT2VrVjNWMmhqVGsxNldYZE5la1UxVFVSQmQwMUVRWGRYYWtJeFRWVlJkMUZuV1VSV1VWRkVSRVIwUW1OSVFuTmFVMEpZWWpOS2MxcElaSEJhUjFWblVrZFdNbHBYZUhaalIxWjVTVVpLYkdKSFJqQmhWemwxWTNsQ1JGcFlTakJoVjFwd1dUSkdNR0ZYT1hWSlJVWXhaRWRvZG1OdGJEQmxWRVZNVFVGclIwRXhWVVZEZDNkRFVucFplRVY2UVZKQ1owNVdRa0Z2VFVOclJuZGpSM2hzU1VWc2RWbDVOSGhEZWtGS1FtZE9Wa0pCV1ZSQmJGWlVUVWhaZDBWQldVaExiMXBKZW1vd1EwRlJXVVpMTkVWRlFVTkpSRmxuUVVWaWMxRkxRemswVUhKc1YyMWFXRzVZWjNSNGVtUldTa3c0VkRCVFIxbHVaMFJTUjNCdVoyNHpUalpRVkRoS1RVVmlOMFpFYVRSaVFtMVFhRU51V2pNdmMzRTJVRVl2WTBkalMxaFhjMHcxZGs5MFpWSm9lVW8wTlhnelFWTlFOMk5QUWl0aFlXODVNR1pqY0hoVGRpOUZXa1ppYm1sQllrNW5Xa2RvU1dod1NXODBTRFpOU1VnelRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaamhEUVZGQmQwaDNXVVJXVWpCcVFrSm5kMFp2UVZWMU4wUmxiMVpuZW1sS2NXdHBjRzVsZG5JemNuSTVja3hLUzNOM1VtZFpTVXQzV1VKQ1VWVklRVkZGUlU5cVFUUk5SRmxIUTBOelIwRlJWVVpDZWtGQ2FHbHdiMlJJVW5kUGFUaDJZakpPZW1ORE5XaGpTRUp6V2xNMWFtSXlNSFppTWs1NlkwUkJla3hYUm5kalIzaHNZMjA1ZG1SSFRtaGFlazEzVG5kWlJGWlNNR1pDUkVGM1RHcEJjMjlEY1dkTFNWbHRZVWhTTUdORWIzWk1NazU1WWtNMWFHTklRbk5hVXpWcVlqSXdkbGxZUW5kaVIxWjVZakk1TUZreVJtNU5lVFZxWTIxM2QwaFJXVVJXVWpCUFFrSlpSVVpFT0hac1EwNVNNREZFU20xcFp6azNZa0k0TldNcmJHdEhTMXBOUVRSSFFURlZaRVIzUlVJdmQxRkZRWGRKUWtKcVFWRkNaMjl4YUd0cFJ6a3lUbXRDWjBsQ1FrRkpSa0ZFUVV0Q1oyZHhhR3RxVDFCUlVVUkJkMDV2UVVSQ2JFRnFRa0ZZYUZOeE5VbDVTMjluVFVOUWRIYzBPVEJDWVVJMk56ZERZVVZIU2xoMVpsRkNMMFZ4V2tka05rTlRhbWxEZEU5dWRVMVVZbGhXV0cxNGVHTjRabXREVFZGRVZGTlFlR0Z5V2xoMlRuSnJlRlV6Vkd0VlRVa3pNM2w2ZGtaV1ZsSlVOSGQ0VjBwRE9UazBUM05rWTFvMEsxSkhUbk5aUkhsU05XZHRaSEl3YmtSSFp6MGlMQ0pOU1VsRFVYcERRMEZqYldkQmQwbENRV2RKU1V4aldEaHBUa3hHVXpWVmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhkYWVrVmlUVUpyUjBFeFZVVkJkM2RUVVZoQ2QySkhWV2RWYlRsMlpFTkNSRkZUUVhSSlJXTjZUVk5aZDBwQldVUldVVkZNUkVJeFFtTklRbk5hVTBKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVlJOUWtWSFFURlZSVU5uZDB0UldFSjNZa2RWWjFOWE5XcE1ha1ZNVFVGclIwRXhWVVZDYUUxRFZsWk5kMGhvWTA1TlZGRjNUa1JOZDAxVVozaFBWRUV5VjJoalRrMTZhM2RPUkUxM1RWUm5lRTlVUVRKWGFrSnVUVkp6ZDBkUldVUldVVkZFUkVKS1FtTklRbk5hVTBKVFlqSTVNRWxGVGtKSlF6Qm5VbnBOZUVwcVFXdENaMDVXUWtGelRVaFZSbmRqUjNoc1NVVk9iR051VW5CYWJXeHFXVmhTY0dJeU5HZFJXRll3WVVjNWVXRllValZOVWsxM1JWRlpSRlpSVVV0RVFYQkNZMGhDYzFwVFFrcGliVTExVFZGemQwTlJXVVJXVVZGSFJYZEtWbFY2UWpKTlFrRkhRbmx4UjFOTk5EbEJaMFZIUWxOMVFrSkJRV2xCTWtsQlFrcHFjRXg2TVVGamNWUjBhM2xLZVdkU1RXTXpVa05XT0dOWGFsUnVTR05HUW1KYVJIVlhiVUpUY0ROYVNIUm1WR3BxVkhWNGVFVjBXQzh4U0RkWmVWbHNNMG8yV1ZKaVZIcENVRVZXYjBFdlZtaFpSRXRZTVVSNWVFNUNNR05VWkdSeFdHdzFaSFpOVm5wMFN6VXhOMGxFZGxsMVZsUmFXSEJ0YTA5c1JVdE5ZVTVEVFVWQmQwaFJXVVJXVWpCUFFrSlpSVVpNZFhjemNVWlpUVFJwWVhCSmNWb3pjalk1TmpZdllYbDVVM0pOUVRoSFFURlZaRVYzUlVJdmQxRkdUVUZOUWtGbU9IZEVaMWxFVmxJd1VFRlJTQzlDUVZGRVFXZEZSMDFCYjBkRFEzRkhVMDAwT1VKQlRVUkJNbWRCVFVkVlEwMVJRMFEyWTBoRlJtdzBZVmhVVVZreVpUTjJPVWQzVDBGRldreDFUaXQ1VW1oSVJrUXZNMjFsYjNsb2NHMTJUM2RuVUZWdVVGZFVlRzVUTkdGMEszRkplRlZEVFVjeGJXbG9SRXN4UVROVlZEZ3lUbEY2TmpCcGJVOXNUVEkzYW1Ka2IxaDBNbEZtZVVaTmJTdFphR2xrUkd0TVJqRjJURlZoWjAwMlFtZEVOVFpMZVV0QlBUMGlYWDAuZXlKdmNtbG5hVzVoYkZSeVlXNXpZV04wYVc5dVNXUWlPaUl5TURBd01EQXhNREkwT1Rrek1qazVJaXdpWVhWMGIxSmxibVYzVUhKdlpIVmpkRWxrSWpvaVkyOXRMbWRsZEhObGMzTnBiMjR1YjNKbkxuQnliMTl6ZFdKZk0xOXRiMjUwYUhNaUxDSndjbTlrZFdOMFNXUWlPaUpqYjIwdVoyVjBjMlZ6YzJsdmJpNXZjbWN1Y0hKdlgzTjFZaUlzSW1GMWRHOVNaVzVsZDFOMFlYUjFjeUk2TVN3aWNtVnVaWGRoYkZCeWFXTmxJam8xT1Rrd0xDSmpkWEp5Wlc1amVTSTZJa0ZWUkNJc0luTnBaMjVsWkVSaGRHVWlPakUzTlRrM01qYzRNemcwTlRBc0ltVnVkbWx5YjI1dFpXNTBJam9pVTJGdVpHSnZlQ0lzSW5KbFkyVnVkRk4xWW5OamNtbHdkR2x2YmxOMFlYSjBSR0YwWlNJNk1UYzFPVGN5TnpjM09EQXdNQ3dpY21WdVpYZGhiRVJoZEdVaU9qRTNOVGszTWpjNU56QXdNREFzSW1Gd2NGUnlZVzV6WVdOMGFXOXVTV1FpT2lJM01EUTRPVGMwTmprNU1ETXpPRE01TVRraWZRLng5ZXg3YUZsbUhKM1UyODZaTFBsdVZYNUVTMFBqZ1Z6SVZPeHh6S1Zqck5qUmktR1ZzU0h1RFNKYnpfd2tGMHpCQnR2RWNPT2dPbmpJcWlIVlJQbU1BIiwic3RhdHVzIjoxfSwidmVyc2lvbiI6IjIuMCIsInNpZ25lZERhdGUiOjE3NTk3Mjc4Mzg0NTB9.5oUhZVZOZp-SSGvLbPi6VWhn_ZCB4Ub7SmvwzFg-w4Z19cnzY3Bof8tCiZAWzBAQRl9p_BoYgQun-JfAY1o9Cg"
            }
            ''')

            e04_cancel_downgrade_to_3_months: dict[str, base.JSONValue] = json.loads('''
            {
            "signedPayload": "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJub3RpZmljYXRpb25UeXBlIjoiRElEX0NIQU5HRV9SRU5FV0FMX1BSRUYiLCJub3RpZmljYXRpb25VVUlEIjoiYTdhNTMwZjgtMmUwMy00YjE2LWJhNGMtY2VlNTA3MjVmOGQ4IiwiZGF0YSI6eyJhcHBBcHBsZUlkIjoxNDcwMTY4ODY4LCJidW5kbGVJZCI6ImNvbS5sb2tpLXByb2plY3QubG9raS1tZXNzZW5nZXIiLCJidW5kbGVWZXJzaW9uIjoiNjM3IiwiZW52aXJvbm1lbnQiOiJTYW5kYm94Iiwic2lnbmVkVHJhbnNhY3Rpb25JbmZvIjoiZXlKaGJHY2lPaUpGVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxGVFZSRFEwRTNZV2RCZDBsQ1FXZEpVVkk0UzBoNlpHNDFOVFJhTDFWdmNtRmtUbmc1ZEhwQlMwSm5aM0ZvYTJwUFVGRlJSRUY2UWpGTlZWRjNVV2RaUkZaUlVVUkVSSFJDWTBoQ2MxcFRRbGhpTTBweldraGtjRnBIVldkU1IxWXlXbGQ0ZG1OSFZubEpSa3BzWWtkR01HRlhPWFZqZVVKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVXhOUVd0SFFURlZSVU4zZDBOU2VsbDRSWHBCVWtKblRsWkNRVzlOUTJ0R2QyTkhlR3hKUld4MVdYazBlRU42UVVwQ1owNVdRa0ZaVkVGc1ZsUk5RalJZUkZSSk1VMUVhM2hQVkVVMVRrUlJNVTFXYjFoRVZFa3pUVlJCZUUxNlJUTk9SR041VFRGdmQyZGFTWGhSUkVFclFtZE9Wa0pCVFUxT01VSjVZakpSWjFKVlRrUkpSVEZvV1hsQ1FtTklRV2RWTTFKMlkyMVZaMWxYTld0SlIyeFZaRmMxYkdONVFsUmtSemw1V2xOQ1UxcFhUbXhoV0VJd1NVWk9jRm95TlhCaWJXTjRURVJCY1VKblRsWkNRWE5OU1RCR2QyTkhlR3hKUm1SMlkyMTRhMlF5Ykd0YVUwSkZXbGhhYkdKSE9YZGFXRWxuVlcxV2MxbFlVbkJpTWpWNlRWSk5kMFZSV1VSV1VWRkxSRUZ3UW1OSVFuTmFVMEpLWW0xTmRVMVJjM2REVVZsRVZsRlJSMFYzU2xaVmVrSmFUVUpOUjBKNWNVZFRUVFE1UVdkRlIwTkRjVWRUVFRRNVFYZEZTRUV3U1VGQ1RtNVdkbWhqZGpkcFZDczNSWGcxZEVKTlFtZHlVWE53U0hwSmMxaFNhVEJaZUdabGF6ZHNkamgzUlcxcUwySklhVmQwVG5kS2NXTXlRbTlJZW5OUmFVVnFVRGRMUmtsSlMyYzBXVGg1TUM5dWVXNTFRVzFxWjJkSlNVMUpTVU5DUkVGTlFtZE9Wa2hTVFVKQlpqaEZRV3BCUVUxQ09FZEJNVlZrU1hkUldVMUNZVUZHUkRoMmJFTk9VakF4UkVwdGFXYzVOMkpDT0RWaksyeHJSMHRhVFVoQlIwTkRjMGRCVVZWR1FuZEZRa0pIVVhkWmFrRjBRbWRuY2tKblJVWkNVV04zUVc5WmFHRklVakJqUkc5MlRESk9iR051VW5wTWJVWjNZMGQ0YkV4dFRuWmlVemt6WkRKU2VWcDZXWFZhUjFaNVRVUkZSME5EYzBkQlVWVkdRbnBCUW1ocFZtOWtTRkozVDJrNGRtSXlUbnBqUXpWb1kwaENjMXBUTldwaU1qQjJZakpPZW1ORVFYcE1XR1F6V2toS2JrNXFRWGxOU1VsQ1NHZFpSRlpTTUdkQ1NVbENSbFJEUTBGU1JYZG5aMFZPUW1kdmNXaHJhVWM1TWs1clFsRlpRazFKU0N0TlNVaEVRbWRuY2tKblJVWkNVV05EUVdwRFFuUm5lVUp6TVVwc1lrZHNhR0p0VG14SlJ6bDFTVWhTYjJGWVRXZFpNbFo1WkVkc2JXRlhUbWhrUjFWbldXNXJaMWxYTlRWSlNFSm9ZMjVTTlVsSFJucGpNMVowV2xoTloxbFhUbXBhV0VJd1dWYzFhbHBUUW5aYWFVSXdZVWRWWjJSSGFHeGlhVUpvWTBoQ2MyRlhUbWhaYlhoc1NVaE9NRmxYTld0WldFcHJTVWhTYkdOdE1YcEpSMFoxV2tOQ2FtSXlOV3RoV0ZKd1lqSTFla2xIT1cxSlNGWjZXbE4zWjFreVZubGtSMnh0WVZkT2FHUkhWV2RqUnpsellWZE9OVWxIUm5WYVEwSnFXbGhLTUdGWFduQlpNa1l3WVZjNWRVbElRbmxaVjA0d1lWZE9iRWxJVGpCWldGSnNZbGRXZFdSSVRYVk5SRmxIUTBOelIwRlJWVVpDZDBsQ1JtbHdiMlJJVW5kUGFUaDJaRE5rTTB4dFJuZGpSM2hzVEcxT2RtSlRPV3BhV0Vvd1lWZGFjRmt5UmpCYVYwWXhaRWRvZG1OdGJEQmxVemgzU0ZGWlJGWlNNRTlDUWxsRlJrbEdhVzlITkhkTlRWWkJNV3QxT1hwS2JVZE9VRUZXYmpObGNVMUJORWRCTVZWa1JIZEZRaTkzVVVWQmQwbElaMFJCVVVKbmIzRm9hMmxIT1RKT2EwSm5jMEpDUVVsR1FVUkJTMEpuWjNGb2EycFBVRkZSUkVGM1RuQkJSRUp0UVdwRlFTdHhXRzVTUlVNM2FGaEpWMVpNYzB4NGVtNXFVbkJKZWxCbU4xWkllamxXTDBOVWJUZ3JURXBzY2xGbGNHNXRZMUIyUjB4T1kxZzJXRkJ1YkdOblRFRkJha1ZCTlVscVRscExaMmMxY0ZFM09XdHVSalJKWWxSWVpFdDJPSFoxZEVsRVRWaEViV3BRVmxRelpFZDJSblJ6UjFKM1dFOTVkMUl5YTFwRFpGTnlabVZ2ZENJc0lrMUpTVVJHYWtORFFYQjVaMEYzU1VKQlowbFZTWE5IYUZKM2NEQmpNbTUyVlRSWlUzbGpZV1pRVkdwNllrNWpkME5uV1VsTGIxcEplbW93UlVGM1RYZGFla1ZpVFVKclIwRXhWVVZCZDNkVFVWaENkMkpIVldkVmJUbDJaRU5DUkZGVFFYUkpSV042VFZOWmQwcEJXVVJXVVZGTVJFSXhRbU5JUW5OYVUwSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlZSTlFrVkhRVEZWUlVObmQwdFJXRUozWWtkVloxTlhOV3BNYWtWTVRVRnJSMEV4VlVWQ2FFMURWbFpOZDBob1kwNU5ha1YzVFhwRk0wMXFRWHBPZWtWM1YyaGpUazE2V1hkTmVrVTFUVVJCZDAxRVFYZFhha0l4VFZWUmQxRm5XVVJXVVZGRVJFUjBRbU5JUW5OYVUwSllZak5LYzFwSVpIQmFSMVZuVWtkV01scFhlSFpqUjFaNVNVWktiR0pIUmpCaFZ6bDFZM2xDUkZwWVNqQmhWMXB3V1RKR01HRlhPWFZKUlVZeFpFZG9kbU50YkRCbFZFVk1UVUZyUjBFeFZVVkRkM2REVW5wWmVFVjZRVkpDWjA1V1FrRnZUVU5yUm5kalIzaHNTVVZzZFZsNU5IaERla0ZLUW1kT1ZrSkJXVlJCYkZaVVRVaFpkMFZCV1VoTGIxcEplbW93UTBGUldVWkxORVZGUVVOSlJGbG5RVVZpYzFGTFF6azBVSEpzVjIxYVdHNVlaM1I0ZW1SV1NrdzRWREJUUjFsdVowUlNSM0J1WjI0elRqWlFWRGhLVFVWaU4wWkVhVFJpUW0xUWFFTnVXak12YzNFMlVFWXZZMGRqUzFoWGMwdzFkazkwWlZKb2VVbzBOWGd6UVZOUU4yTlBRaXRoWVc4NU1HWmpjSGhUZGk5RldrWmlibWxCWWs1bldrZG9TV2h3U1c4MFNEWk5TVWd6VFVKSlIwRXhWV1JGZDBWQ0wzZFJTVTFCV1VKQlpqaERRVkZCZDBoM1dVUldVakJxUWtKbmQwWnZRVlYxTjBSbGIxWm5lbWxLY1d0cGNHNWxkbkl6Y25JNWNreEtTM04zVW1kWlNVdDNXVUpDVVZWSVFWRkZSVTlxUVRSTlJGbEhRME56UjBGUlZVWkNla0ZDYUdsd2IyUklVbmRQYVRoMllqSk9lbU5ETldoalNFSnpXbE0xYW1JeU1IWmlNazU2WTBSQmVreFhSbmRqUjNoc1kyMDVkbVJIVG1oYWVrMTNUbmRaUkZaU01HWkNSRUYzVEdwQmMyOURjV2RMU1ZsdFlVaFNNR05FYjNaTU1rNTVZa00xYUdOSVFuTmFVelZxWWpJd2RsbFlRbmRpUjFaNVlqSTVNRmt5Um01TmVUVnFZMjEzZDBoUldVUldVakJQUWtKWlJVWkVPSFpzUTA1U01ERkVTbTFwWnprM1lrSTROV01yYkd0SFMxcE5RVFJIUVRGVlpFUjNSVUl2ZDFGRlFYZEpRa0pxUVZGQ1oyOXhhR3RwUnpreVRtdENaMGxDUWtGSlJrRkVRVXRDWjJkeGFHdHFUMUJSVVVSQmQwNXZRVVJDYkVGcVFrRllhRk54TlVsNVMyOW5UVU5RZEhjME9UQkNZVUkyTnpkRFlVVkhTbGgxWmxGQ0wwVnhXa2RrTmtOVGFtbERkRTl1ZFUxVVlsaFdXRzE0ZUdONFptdERUVkZFVkZOUWVHRnlXbGgyVG5KcmVGVXpWR3RWVFVrek0zbDZka1pXVmxKVU5IZDRWMHBET1RrMFQzTmtZMW8wSzFKSFRuTlpSSGxTTldkdFpISXdia1JIWnowaUxDSk5TVWxEVVhwRFEwRmpiV2RCZDBsQ1FXZEpTVXhqV0RocFRreEdVelZWZDBObldVbExiMXBKZW1vd1JVRjNUWGRhZWtWaVRVSnJSMEV4VlVWQmQzZFRVVmhDZDJKSFZXZFZiVGwyWkVOQ1JGRlRRWFJKUldONlRWTlpkMHBCV1VSV1VWRk1SRUl4UW1OSVFuTmFVMEpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJWUk5Ra1ZIUVRGVlJVTm5kMHRSV0VKM1lrZFZaMU5YTldwTWFrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmQwaG9ZMDVOVkZGM1RrUk5kMDFVWjNoUFZFRXlWMmhqVGsxNmEzZE9SRTEzVFZSbmVFOVVRVEpYYWtKdVRWSnpkMGRSV1VSV1VWRkVSRUpLUW1OSVFuTmFVMEpUWWpJNU1FbEZUa0pKUXpCblVucE5lRXBxUVd0Q1owNVdRa0Z6VFVoVlJuZGpSM2hzU1VWT2JHTnVVbkJhYld4cVdWaFNjR0l5TkdkUldGWXdZVWM1ZVdGWVVqVk5VazEzUlZGWlJGWlJVVXRFUVhCQ1kwaENjMXBUUWtwaWJVMTFUVkZ6ZDBOUldVUldVVkZIUlhkS1ZsVjZRakpOUWtGSFFubHhSMU5OTkRsQlowVkhRbE4xUWtKQlFXbEJNa2xCUWtwcWNFeDZNVUZqY1ZSMGEzbEtlV2RTVFdNelVrTldPR05YYWxSdVNHTkdRbUphUkhWWGJVSlRjRE5hU0hSbVZHcHFWSFY0ZUVWMFdDOHhTRGRaZVZsc00wbzJXVkppVkhwQ1VFVldiMEV2Vm1oWlJFdFlNVVI1ZUU1Q01HTlVaR1J4V0d3MVpIWk5WbnAwU3pVeE4wbEVkbGwxVmxSYVdIQnRhMDlzUlV0TllVNURUVVZCZDBoUldVUldVakJQUWtKWlJVWk1kWGN6Y1VaWlRUUnBZWEJKY1ZvemNqWTVOall2WVhsNVUzSk5RVGhIUVRGVlpFVjNSVUl2ZDFGR1RVRk5Ra0ZtT0hkRVoxbEVWbEl3VUVGUlNDOUNRVkZFUVdkRlIwMUJiMGREUTNGSFUwMDBPVUpCVFVSQk1tZEJUVWRWUTAxUlEwUTJZMGhGUm13MFlWaFVVVmt5WlROMk9VZDNUMEZGV2t4MVRpdDVVbWhJUmtRdk0yMWxiM2xvY0cxMlQzZG5VRlZ1VUZkVWVHNVROR0YwSzNGSmVGVkRUVWN4Yldsb1JFc3hRVE5WVkRneVRsRjZOakJwYlU5c1RUSTNhbUprYjFoME1sRm1lVVpOYlN0WmFHbGtSR3RNUmpGMlRGVmhaMDAyUW1kRU5UWkxlVXRCUFQwaVhYMC5leUowY21GdWMyRmpkR2x2Ymtsa0lqb2lNakF3TURBd01UQXlOemN3TVRreU9DSXNJbTl5YVdkcGJtRnNWSEpoYm5OaFkzUnBiMjVKWkNJNklqSXdNREF3TURFd01qUTVPVE15T1RraUxDSjNaV0pQY21SbGNreHBibVZKZEdWdFNXUWlPaUl5TURBd01EQXdNVEUwTWpBeU1UUXdJaXdpWW5WdVpHeGxTV1FpT2lKamIyMHViRzlyYVMxd2NtOXFaV04wTG14dmEya3RiV1Z6YzJWdVoyVnlJaXdpY0hKdlpIVmpkRWxrSWpvaVkyOXRMbWRsZEhObGMzTnBiMjR1YjNKbkxuQnliMTl6ZFdJaUxDSnpkV0p6WTNKcGNIUnBiMjVIY205MWNFbGtaVzUwYVdacFpYSWlPaUl5TVRjMU1qZ3hOQ0lzSW5CMWNtTm9ZWE5sUkdGMFpTSTZNVGMxT1RjeU56YzVNREF3TUN3aWIzSnBaMmx1WVd4UWRYSmphR0Z6WlVSaGRHVWlPakUzTlRrek1ERTRNek13TURBc0ltVjRjR2x5WlhORVlYUmxJam94TnpVNU56STNPVGN3TURBd0xDSnhkV0Z1ZEdsMGVTSTZNU3dpZEhsd1pTSTZJa0YxZEc4dFVtVnVaWGRoWW14bElGTjFZbk5qY21sd2RHbHZiaUlzSW1sdVFYQndUM2R1WlhKemFHbHdWSGx3WlNJNklsQlZVa05JUVZORlJDSXNJbk5wWjI1bFpFUmhkR1VpT2pFM05UazNNamM0TmpZeU16RXNJbVZ1ZG1seWIyNXRaVzUwSWpvaVUyRnVaR0p2ZUNJc0luUnlZVzV6WVdOMGFXOXVVbVZoYzI5dUlqb2lVRlZTUTBoQlUwVWlMQ0p6ZEc5eVpXWnliMjUwSWpvaVFWVlRJaXdpYzNSdmNtVm1jbTl1ZEVsa0lqb2lNVFF6TkRZd0lpd2ljSEpwWTJVaU9qRTVPVEFzSW1OMWNuSmxibU41SWpvaVFWVkVJaXdpWVhCd1ZISmhibk5oWTNScGIyNUpaQ0k2SWpjd05EZzVOelEyT1Rrd016TTRNemt4T1NKOS50Sk1FWXMzMlF5cWduaHgzSVRyenBnRVJTSVJpXzFLamZGNUg5RXloZzFaUmIteWhnb1Z3MEtmYkU1Y2ZRRF9KSXhmLUJWWUxYbXpzRzZ0emplRTBjZyIsInNpZ25lZFJlbmV3YWxJbmZvIjoiZXlKaGJHY2lPaUpGVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxGVFZSRFEwRTNZV2RCZDBsQ1FXZEpVVkk0UzBoNlpHNDFOVFJhTDFWdmNtRmtUbmc1ZEhwQlMwSm5aM0ZvYTJwUFVGRlJSRUY2UWpGTlZWRjNVV2RaUkZaUlVVUkVSSFJDWTBoQ2MxcFRRbGhpTTBweldraGtjRnBIVldkU1IxWXlXbGQ0ZG1OSFZubEpSa3BzWWtkR01HRlhPWFZqZVVKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVXhOUVd0SFFURlZSVU4zZDBOU2VsbDRSWHBCVWtKblRsWkNRVzlOUTJ0R2QyTkhlR3hKUld4MVdYazBlRU42UVVwQ1owNVdRa0ZaVkVGc1ZsUk5RalJZUkZSSk1VMUVhM2hQVkVVMVRrUlJNVTFXYjFoRVZFa3pUVlJCZUUxNlJUTk9SR041VFRGdmQyZGFTWGhSUkVFclFtZE9Wa0pCVFUxT01VSjVZakpSWjFKVlRrUkpSVEZvV1hsQ1FtTklRV2RWTTFKMlkyMVZaMWxYTld0SlIyeFZaRmMxYkdONVFsUmtSemw1V2xOQ1UxcFhUbXhoV0VJd1NVWk9jRm95TlhCaWJXTjRURVJCY1VKblRsWkNRWE5OU1RCR2QyTkhlR3hKUm1SMlkyMTRhMlF5Ykd0YVUwSkZXbGhhYkdKSE9YZGFXRWxuVlcxV2MxbFlVbkJpTWpWNlRWSk5kMFZSV1VSV1VWRkxSRUZ3UW1OSVFuTmFVMEpLWW0xTmRVMVJjM2REVVZsRVZsRlJSMFYzU2xaVmVrSmFUVUpOUjBKNWNVZFRUVFE1UVdkRlIwTkRjVWRUVFRRNVFYZEZTRUV3U1VGQ1RtNVdkbWhqZGpkcFZDczNSWGcxZEVKTlFtZHlVWE53U0hwSmMxaFNhVEJaZUdabGF6ZHNkamgzUlcxcUwySklhVmQwVG5kS2NXTXlRbTlJZW5OUmFVVnFVRGRMUmtsSlMyYzBXVGg1TUM5dWVXNTFRVzFxWjJkSlNVMUpTVU5DUkVGTlFtZE9Wa2hTVFVKQlpqaEZRV3BCUVUxQ09FZEJNVlZrU1hkUldVMUNZVUZHUkRoMmJFTk9VakF4UkVwdGFXYzVOMkpDT0RWaksyeHJSMHRhVFVoQlIwTkRjMGRCVVZWR1FuZEZRa0pIVVhkWmFrRjBRbWRuY2tKblJVWkNVV04zUVc5WmFHRklVakJqUkc5MlRESk9iR051VW5wTWJVWjNZMGQ0YkV4dFRuWmlVemt6WkRKU2VWcDZXWFZhUjFaNVRVUkZSME5EYzBkQlVWVkdRbnBCUW1ocFZtOWtTRkozVDJrNGRtSXlUbnBqUXpWb1kwaENjMXBUTldwaU1qQjJZakpPZW1ORVFYcE1XR1F6V2toS2JrNXFRWGxOU1VsQ1NHZFpSRlpTTUdkQ1NVbENSbFJEUTBGU1JYZG5aMFZPUW1kdmNXaHJhVWM1TWs1clFsRlpRazFKU0N0TlNVaEVRbWRuY2tKblJVWkNVV05EUVdwRFFuUm5lVUp6TVVwc1lrZHNhR0p0VG14SlJ6bDFTVWhTYjJGWVRXZFpNbFo1WkVkc2JXRlhUbWhrUjFWbldXNXJaMWxYTlRWSlNFSm9ZMjVTTlVsSFJucGpNMVowV2xoTloxbFhUbXBhV0VJd1dWYzFhbHBUUW5aYWFVSXdZVWRWWjJSSGFHeGlhVUpvWTBoQ2MyRlhUbWhaYlhoc1NVaE9NRmxYTld0WldFcHJTVWhTYkdOdE1YcEpSMFoxV2tOQ2FtSXlOV3RoV0ZKd1lqSTFla2xIT1cxSlNGWjZXbE4zWjFreVZubGtSMnh0WVZkT2FHUkhWV2RqUnpsellWZE9OVWxIUm5WYVEwSnFXbGhLTUdGWFduQlpNa1l3WVZjNWRVbElRbmxaVjA0d1lWZE9iRWxJVGpCWldGSnNZbGRXZFdSSVRYVk5SRmxIUTBOelIwRlJWVVpDZDBsQ1JtbHdiMlJJVW5kUGFUaDJaRE5rTTB4dFJuZGpSM2hzVEcxT2RtSlRPV3BhV0Vvd1lWZGFjRmt5UmpCYVYwWXhaRWRvZG1OdGJEQmxVemgzU0ZGWlJGWlNNRTlDUWxsRlJrbEdhVzlITkhkTlRWWkJNV3QxT1hwS2JVZE9VRUZXYmpObGNVMUJORWRCTVZWa1JIZEZRaTkzVVVWQmQwbElaMFJCVVVKbmIzRm9hMmxIT1RKT2EwSm5jMEpDUVVsR1FVUkJTMEpuWjNGb2EycFBVRkZSUkVGM1RuQkJSRUp0UVdwRlFTdHhXRzVTUlVNM2FGaEpWMVpNYzB4NGVtNXFVbkJKZWxCbU4xWkllamxXTDBOVWJUZ3JURXBzY2xGbGNHNXRZMUIyUjB4T1kxZzJXRkJ1YkdOblRFRkJha1ZCTlVscVRscExaMmMxY0ZFM09XdHVSalJKWWxSWVpFdDJPSFoxZEVsRVRWaEViV3BRVmxRelpFZDJSblJ6UjFKM1dFOTVkMUl5YTFwRFpGTnlabVZ2ZENJc0lrMUpTVVJHYWtORFFYQjVaMEYzU1VKQlowbFZTWE5IYUZKM2NEQmpNbTUyVlRSWlUzbGpZV1pRVkdwNllrNWpkME5uV1VsTGIxcEplbW93UlVGM1RYZGFla1ZpVFVKclIwRXhWVVZCZDNkVFVWaENkMkpIVldkVmJUbDJaRU5DUkZGVFFYUkpSV042VFZOWmQwcEJXVVJXVVZGTVJFSXhRbU5JUW5OYVUwSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlZSTlFrVkhRVEZWUlVObmQwdFJXRUozWWtkVloxTlhOV3BNYWtWTVRVRnJSMEV4VlVWQ2FFMURWbFpOZDBob1kwNU5ha1YzVFhwRk0wMXFRWHBPZWtWM1YyaGpUazE2V1hkTmVrVTFUVVJCZDAxRVFYZFhha0l4VFZWUmQxRm5XVVJXVVZGRVJFUjBRbU5JUW5OYVUwSllZak5LYzFwSVpIQmFSMVZuVWtkV01scFhlSFpqUjFaNVNVWktiR0pIUmpCaFZ6bDFZM2xDUkZwWVNqQmhWMXB3V1RKR01HRlhPWFZKUlVZeFpFZG9kbU50YkRCbFZFVk1UVUZyUjBFeFZVVkRkM2REVW5wWmVFVjZRVkpDWjA1V1FrRnZUVU5yUm5kalIzaHNTVVZzZFZsNU5IaERla0ZLUW1kT1ZrSkJXVlJCYkZaVVRVaFpkMFZCV1VoTGIxcEplbW93UTBGUldVWkxORVZGUVVOSlJGbG5RVVZpYzFGTFF6azBVSEpzVjIxYVdHNVlaM1I0ZW1SV1NrdzRWREJUUjFsdVowUlNSM0J1WjI0elRqWlFWRGhLVFVWaU4wWkVhVFJpUW0xUWFFTnVXak12YzNFMlVFWXZZMGRqUzFoWGMwdzFkazkwWlZKb2VVbzBOWGd6UVZOUU4yTlBRaXRoWVc4NU1HWmpjSGhUZGk5RldrWmlibWxCWWs1bldrZG9TV2h3U1c4MFNEWk5TVWd6VFVKSlIwRXhWV1JGZDBWQ0wzZFJTVTFCV1VKQlpqaERRVkZCZDBoM1dVUldVakJxUWtKbmQwWnZRVlYxTjBSbGIxWm5lbWxLY1d0cGNHNWxkbkl6Y25JNWNreEtTM04zVW1kWlNVdDNXVUpDVVZWSVFWRkZSVTlxUVRSTlJGbEhRME56UjBGUlZVWkNla0ZDYUdsd2IyUklVbmRQYVRoMllqSk9lbU5ETldoalNFSnpXbE0xYW1JeU1IWmlNazU2WTBSQmVreFhSbmRqUjNoc1kyMDVkbVJIVG1oYWVrMTNUbmRaUkZaU01HWkNSRUYzVEdwQmMyOURjV2RMU1ZsdFlVaFNNR05FYjNaTU1rNTVZa00xYUdOSVFuTmFVelZxWWpJd2RsbFlRbmRpUjFaNVlqSTVNRmt5Um01TmVUVnFZMjEzZDBoUldVUldVakJQUWtKWlJVWkVPSFpzUTA1U01ERkVTbTFwWnprM1lrSTROV01yYkd0SFMxcE5RVFJIUVRGVlpFUjNSVUl2ZDFGRlFYZEpRa0pxUVZGQ1oyOXhhR3RwUnpreVRtdENaMGxDUWtGSlJrRkVRVXRDWjJkeGFHdHFUMUJSVVVSQmQwNXZRVVJDYkVGcVFrRllhRk54TlVsNVMyOW5UVU5RZEhjME9UQkNZVUkyTnpkRFlVVkhTbGgxWmxGQ0wwVnhXa2RrTmtOVGFtbERkRTl1ZFUxVVlsaFdXRzE0ZUdONFptdERUVkZFVkZOUWVHRnlXbGgyVG5KcmVGVXpWR3RWVFVrek0zbDZka1pXVmxKVU5IZDRWMHBET1RrMFQzTmtZMW8wSzFKSFRuTlpSSGxTTldkdFpISXdia1JIWnowaUxDSk5TVWxEVVhwRFEwRmpiV2RCZDBsQ1FXZEpTVXhqV0RocFRreEdVelZWZDBObldVbExiMXBKZW1vd1JVRjNUWGRhZWtWaVRVSnJSMEV4VlVWQmQzZFRVVmhDZDJKSFZXZFZiVGwyWkVOQ1JGRlRRWFJKUldONlRWTlpkMHBCV1VSV1VWRk1SRUl4UW1OSVFuTmFVMEpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJWUk5Ra1ZIUVRGVlJVTm5kMHRSV0VKM1lrZFZaMU5YTldwTWFrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmQwaG9ZMDVOVkZGM1RrUk5kMDFVWjNoUFZFRXlWMmhqVGsxNmEzZE9SRTEzVFZSbmVFOVVRVEpYYWtKdVRWSnpkMGRSV1VSV1VWRkVSRUpLUW1OSVFuTmFVMEpUWWpJNU1FbEZUa0pKUXpCblVucE5lRXBxUVd0Q1owNVdRa0Z6VFVoVlJuZGpSM2hzU1VWT2JHTnVVbkJhYld4cVdWaFNjR0l5TkdkUldGWXdZVWM1ZVdGWVVqVk5VazEzUlZGWlJGWlJVVXRFUVhCQ1kwaENjMXBUUWtwaWJVMTFUVkZ6ZDBOUldVUldVVkZIUlhkS1ZsVjZRakpOUWtGSFFubHhSMU5OTkRsQlowVkhRbE4xUWtKQlFXbEJNa2xCUWtwcWNFeDZNVUZqY1ZSMGEzbEtlV2RTVFdNelVrTldPR05YYWxSdVNHTkdRbUphUkhWWGJVSlRjRE5hU0hSbVZHcHFWSFY0ZUVWMFdDOHhTRGRaZVZsc00wbzJXVkppVkhwQ1VFVldiMEV2Vm1oWlJFdFlNVVI1ZUU1Q01HTlVaR1J4V0d3MVpIWk5WbnAwU3pVeE4wbEVkbGwxVmxSYVdIQnRhMDlzUlV0TllVNURUVVZCZDBoUldVUldVakJQUWtKWlJVWk1kWGN6Y1VaWlRUUnBZWEJKY1ZvemNqWTVOall2WVhsNVUzSk5RVGhIUVRGVlpFVjNSVUl2ZDFGR1RVRk5Ra0ZtT0hkRVoxbEVWbEl3VUVGUlNDOUNRVkZFUVdkRlIwMUJiMGREUTNGSFUwMDBPVUpCVFVSQk1tZEJUVWRWUTAxUlEwUTJZMGhGUm13MFlWaFVVVmt5WlROMk9VZDNUMEZGV2t4MVRpdDVVbWhJUmtRdk0yMWxiM2xvY0cxMlQzZG5VRlZ1VUZkVWVHNVROR0YwSzNGSmVGVkRUVWN4Yldsb1JFc3hRVE5WVkRneVRsRjZOakJwYlU5c1RUSTNhbUprYjFoME1sRm1lVVpOYlN0WmFHbGtSR3RNUmpGMlRGVmhaMDAyUW1kRU5UWkxlVXRCUFQwaVhYMC5leUp2Y21sbmFXNWhiRlJ5WVc1ellXTjBhVzl1U1dRaU9pSXlNREF3TURBeE1ESTBPVGt6TWprNUlpd2lZWFYwYjFKbGJtVjNVSEp2WkhWamRFbGtJam9pWTI5dExtZGxkSE5sYzNOcGIyNHViM0puTG5CeWIxOXpkV0lpTENKd2NtOWtkV04wU1dRaU9pSmpiMjB1WjJWMGMyVnpjMmx2Ymk1dmNtY3VjSEp2WDNOMVlpSXNJbUYxZEc5U1pXNWxkMU4wWVhSMWN5STZNU3dpY21WdVpYZGhiRkJ5YVdObElqb3hPVGt3TENKamRYSnlaVzVqZVNJNklrRlZSQ0lzSW5OcFoyNWxaRVJoZEdVaU9qRTNOVGszTWpjNE5qWXlNekVzSW1WdWRtbHliMjV0Wlc1MElqb2lVMkZ1WkdKdmVDSXNJbkpsWTJWdWRGTjFZbk5qY21sd2RHbHZibE4wWVhKMFJHRjBaU0k2TVRjMU9UY3lOemMzT0RBd01Dd2ljbVZ1WlhkaGJFUmhkR1VpT2pFM05UazNNamM1TnpBd01EQXNJbUZ3Y0ZSeVlXNXpZV04wYVc5dVNXUWlPaUkzTURRNE9UYzBOams1TURNek9ETTVNVGtpZlEuVElTSlZGXzBWc0tEYzdVQXdUM1o0dk04b1NSY28wY1BHUTR6NnIza0FpNDRZYTFmMVJscHBmY3k0OVFybmhaR3F1YlB1c1luQlZHOGZNVUNYaVgzanciLCJzdGF0dXMiOjF9LCJ2ZXJzaW9uIjoiMi4wIiwic2lnbmVkRGF0ZSI6MTc1OTcyNzg2NjIzMX0.y8U1quxZRXQuifyjJesOCA2it_X2fxQ1TdX0dBE4d4iiT9RFZ-DwXTuRt88N-j90uu8YvbdRJdjVrEanrf3Img"
            }
            ''')

            e05_disable_auto_renew: dict[str, base.JSONValue] = json.loads('''
            {
            "signedPayload": "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJub3RpZmljYXRpb25UeXBlIjoiRElEX0NIQU5HRV9SRU5FV0FMX1NUQVRVUyIsInN1YnR5cGUiOiJBVVRPX1JFTkVXX0RJU0FCTEVEIiwibm90aWZpY2F0aW9uVVVJRCI6IjJiN2VkMzk5LThhODgtNDQ0NS04YTU5LTNkMjAxNzYzN2MxNSIsImRhdGEiOnsiYXBwQXBwbGVJZCI6MTQ3MDE2ODg2OCwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwiYnVuZGxlVmVyc2lvbiI6IjYzNyIsImVudmlyb25tZW50IjoiU2FuZGJveCIsInNpZ25lZFRyYW5zYWN0aW9uSW5mbyI6ImV5SmhiR2NpT2lKRlV6STFOaUlzSW5nMVl5STZXeUpOU1VsRlRWUkRRMEUzWVdkQmQwbENRV2RKVVZJNFMwaDZaRzQxTlRSYUwxVnZjbUZrVG5nNWRIcEJTMEpuWjNGb2EycFBVRkZSUkVGNlFqRk5WVkYzVVdkWlJGWlJVVVJFUkhSQ1kwaENjMXBUUWxoaU0wcHpXa2hrY0ZwSFZXZFNSMVl5V2xkNGRtTkhWbmxKUmtwc1lrZEdNR0ZYT1hWamVVSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlV4TlFXdEhRVEZWUlVOM2QwTlNlbGw0UlhwQlVrSm5UbFpDUVc5TlEydEdkMk5IZUd4SlJXeDFXWGswZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOUWpSWVJGUkpNVTFFYTNoUFZFVTFUa1JSTVUxV2IxaEVWRWt6VFZSQmVFMTZSVE5PUkdONVRURnZkMmRhU1hoUlJFRXJRbWRPVmtKQlRVMU9NVUo1WWpKUloxSlZUa1JKUlRGb1dYbENRbU5JUVdkVk0xSjJZMjFWWjFsWE5XdEpSMnhWWkZjMWJHTjVRbFJrUnpsNVdsTkNVMXBYVG14aFdFSXdTVVpPY0ZveU5YQmliV040VEVSQmNVSm5UbFpDUVhOTlNUQkdkMk5IZUd4SlJtUjJZMjE0YTJReWJHdGFVMEpGV2xoYWJHSkhPWGRhV0VsblZXMVdjMWxZVW5CaU1qVjZUVkpOZDBWUldVUldVVkZMUkVGd1FtTklRbk5hVTBKS1ltMU5kVTFSYzNkRFVWbEVWbEZSUjBWM1NsWlZla0phVFVKTlIwSjVjVWRUVFRRNVFXZEZSME5EY1VkVFRUUTVRWGRGU0VFd1NVRkNUbTVXZG1oamRqZHBWQ3MzUlhnMWRFSk5RbWR5VVhOd1NIcEpjMWhTYVRCWmVHWmxhemRzZGpoM1JXMXFMMkpJYVZkMFRuZEtjV015UW05SWVuTlJhVVZxVURkTFJrbEpTMmMwV1RoNU1DOXVlVzUxUVcxcVoyZEpTVTFKU1VOQ1JFRk5RbWRPVmtoU1RVSkJaamhGUVdwQlFVMUNPRWRCTVZWa1NYZFJXVTFDWVVGR1JEaDJiRU5PVWpBeFJFcHRhV2M1TjJKQ09EVmpLMnhyUjB0YVRVaEJSME5EYzBkQlVWVkdRbmRGUWtKSFVYZFpha0YwUW1kbmNrSm5SVVpDVVdOM1FXOVphR0ZJVWpCalJHOTJUREpPYkdOdVVucE1iVVozWTBkNGJFeHRUblppVXprelpESlNlVnA2V1hWYVIxWjVUVVJGUjBORGMwZEJVVlZHUW5wQlFtaHBWbTlrU0ZKM1QyazRkbUl5VG5walF6Vm9ZMGhDYzFwVE5XcGlNakIyWWpKT2VtTkVRWHBNV0dReldraEtiazVxUVhsTlNVbENTR2RaUkZaU01HZENTVWxDUmxSRFEwRlNSWGRuWjBWT1FtZHZjV2hyYVVjNU1rNXJRbEZaUWsxSlNDdE5TVWhFUW1kbmNrSm5SVVpDVVdORFFXcERRblJuZVVKek1VcHNZa2RzYUdKdFRteEpSemwxU1VoU2IyRllUV2RaTWxaNVpFZHNiV0ZYVG1oa1IxVm5XVzVyWjFsWE5UVkpTRUpvWTI1U05VbEhSbnBqTTFaMFdsaE5aMWxYVG1wYVdFSXdXVmMxYWxwVFFuWmFhVUl3WVVkVloyUkhhR3hpYVVKb1kwaENjMkZYVG1oWmJYaHNTVWhPTUZsWE5XdFpXRXByU1VoU2JHTnRNWHBKUjBaMVdrTkNhbUl5Tld0aFdGSndZakkxZWtsSE9XMUpTRlo2V2xOM1oxa3lWbmxrUjJ4dFlWZE9hR1JIVldkalJ6bHpZVmRPTlVsSFJuVmFRMEpxV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxJUW5sWlYwNHdZVmRPYkVsSVRqQlpXRkpzWWxkV2RXUklUWFZOUkZsSFEwTnpSMEZSVlVaQ2QwbENSbWx3YjJSSVVuZFBhVGgyWkROa00weHRSbmRqUjNoc1RHMU9kbUpUT1dwYVdFb3dZVmRhY0ZreVJqQmFWMFl4WkVkb2RtTnRiREJsVXpoM1NGRlpSRlpTTUU5Q1FsbEZSa2xHYVc5SE5IZE5UVlpCTVd0MU9YcEtiVWRPVUVGV2JqTmxjVTFCTkVkQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlVVSm5iM0ZvYTJsSE9USk9hMEpuYzBKQ1FVbEdRVVJCUzBKblozRm9hMnBQVUZGUlJFRjNUbkJCUkVKdFFXcEZRU3R4V0c1U1JVTTNhRmhKVjFaTWMweDRlbTVxVW5CSmVsQm1OMVpJZWpsV0wwTlViVGdyVEVwc2NsRmxjRzV0WTFCMlIweE9ZMWcyV0ZCdWJHTm5URUZCYWtWQk5VbHFUbHBMWjJjMWNGRTNPV3R1UmpSSllsUllaRXQyT0haMWRFbEVUVmhFYldwUVZsUXpaRWQyUm5SelIxSjNXRTk1ZDFJeWExcERaRk55Wm1WdmRDSXNJazFKU1VSR2FrTkRRWEI1WjBGM1NVSkJaMGxWU1hOSGFGSjNjREJqTW01MlZUUlpVM2xqWVdaUVZHcDZZazVqZDBObldVbExiMXBKZW1vd1JVRjNUWGRhZWtWaVRVSnJSMEV4VlVWQmQzZFRVVmhDZDJKSFZXZFZiVGwyWkVOQ1JGRlRRWFJKUldONlRWTlpkMHBCV1VSV1VWRk1SRUl4UW1OSVFuTmFVMEpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJWUk5Ra1ZIUVRGVlJVTm5kMHRSV0VKM1lrZFZaMU5YTldwTWFrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmQwaG9ZMDVOYWtWM1RYcEZNMDFxUVhwT2VrVjNWMmhqVGsxNldYZE5la1UxVFVSQmQwMUVRWGRYYWtJeFRWVlJkMUZuV1VSV1VWRkVSRVIwUW1OSVFuTmFVMEpZWWpOS2MxcElaSEJhUjFWblVrZFdNbHBYZUhaalIxWjVTVVpLYkdKSFJqQmhWemwxWTNsQ1JGcFlTakJoVjFwd1dUSkdNR0ZYT1hWSlJVWXhaRWRvZG1OdGJEQmxWRVZNVFVGclIwRXhWVVZEZDNkRFVucFplRVY2UVZKQ1owNVdRa0Z2VFVOclJuZGpSM2hzU1VWc2RWbDVOSGhEZWtGS1FtZE9Wa0pCV1ZSQmJGWlVUVWhaZDBWQldVaExiMXBKZW1vd1EwRlJXVVpMTkVWRlFVTkpSRmxuUVVWaWMxRkxRemswVUhKc1YyMWFXRzVZWjNSNGVtUldTa3c0VkRCVFIxbHVaMFJTUjNCdVoyNHpUalpRVkRoS1RVVmlOMFpFYVRSaVFtMVFhRU51V2pNdmMzRTJVRVl2WTBkalMxaFhjMHcxZGs5MFpWSm9lVW8wTlhnelFWTlFOMk5QUWl0aFlXODVNR1pqY0hoVGRpOUZXa1ppYm1sQllrNW5Xa2RvU1dod1NXODBTRFpOU1VnelRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaamhEUVZGQmQwaDNXVVJXVWpCcVFrSm5kMFp2UVZWMU4wUmxiMVpuZW1sS2NXdHBjRzVsZG5JemNuSTVja3hLUzNOM1VtZFpTVXQzV1VKQ1VWVklRVkZGUlU5cVFUUk5SRmxIUTBOelIwRlJWVVpDZWtGQ2FHbHdiMlJJVW5kUGFUaDJZakpPZW1ORE5XaGpTRUp6V2xNMWFtSXlNSFppTWs1NlkwUkJla3hYUm5kalIzaHNZMjA1ZG1SSFRtaGFlazEzVG5kWlJGWlNNR1pDUkVGM1RHcEJjMjlEY1dkTFNWbHRZVWhTTUdORWIzWk1NazU1WWtNMWFHTklRbk5hVXpWcVlqSXdkbGxZUW5kaVIxWjVZakk1TUZreVJtNU5lVFZxWTIxM2QwaFJXVVJXVWpCUFFrSlpSVVpFT0hac1EwNVNNREZFU20xcFp6azNZa0k0TldNcmJHdEhTMXBOUVRSSFFURlZaRVIzUlVJdmQxRkZRWGRKUWtKcVFWRkNaMjl4YUd0cFJ6a3lUbXRDWjBsQ1FrRkpSa0ZFUVV0Q1oyZHhhR3RxVDFCUlVVUkJkMDV2UVVSQ2JFRnFRa0ZZYUZOeE5VbDVTMjluVFVOUWRIYzBPVEJDWVVJMk56ZERZVVZIU2xoMVpsRkNMMFZ4V2tka05rTlRhbWxEZEU5dWRVMVVZbGhXV0cxNGVHTjRabXREVFZGRVZGTlFlR0Z5V2xoMlRuSnJlRlV6Vkd0VlRVa3pNM2w2ZGtaV1ZsSlVOSGQ0VjBwRE9UazBUM05rWTFvMEsxSkhUbk5aUkhsU05XZHRaSEl3YmtSSFp6MGlMQ0pOU1VsRFVYcERRMEZqYldkQmQwbENRV2RKU1V4aldEaHBUa3hHVXpWVmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhkYWVrVmlUVUpyUjBFeFZVVkJkM2RUVVZoQ2QySkhWV2RWYlRsMlpFTkNSRkZUUVhSSlJXTjZUVk5aZDBwQldVUldVVkZNUkVJeFFtTklRbk5hVTBKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVlJOUWtWSFFURlZSVU5uZDB0UldFSjNZa2RWWjFOWE5XcE1ha1ZNVFVGclIwRXhWVVZDYUUxRFZsWk5kMGhvWTA1TlZGRjNUa1JOZDAxVVozaFBWRUV5VjJoalRrMTZhM2RPUkUxM1RWUm5lRTlVUVRKWGFrSnVUVkp6ZDBkUldVUldVVkZFUkVKS1FtTklRbk5hVTBKVFlqSTVNRWxGVGtKSlF6Qm5VbnBOZUVwcVFXdENaMDVXUWtGelRVaFZSbmRqUjNoc1NVVk9iR051VW5CYWJXeHFXVmhTY0dJeU5HZFJXRll3WVVjNWVXRllValZOVWsxM1JWRlpSRlpSVVV0RVFYQkNZMGhDYzFwVFFrcGliVTExVFZGemQwTlJXVVJXVVZGSFJYZEtWbFY2UWpKTlFrRkhRbmx4UjFOTk5EbEJaMFZIUWxOMVFrSkJRV2xCTWtsQlFrcHFjRXg2TVVGamNWUjBhM2xLZVdkU1RXTXpVa05XT0dOWGFsUnVTR05HUW1KYVJIVlhiVUpUY0ROYVNIUm1WR3BxVkhWNGVFVjBXQzh4U0RkWmVWbHNNMG8yV1ZKaVZIcENVRVZXYjBFdlZtaFpSRXRZTVVSNWVFNUNNR05VWkdSeFdHdzFaSFpOVm5wMFN6VXhOMGxFZGxsMVZsUmFXSEJ0YTA5c1JVdE5ZVTVEVFVWQmQwaFJXVVJXVWpCUFFrSlpSVVpNZFhjemNVWlpUVFJwWVhCSmNWb3pjalk1TmpZdllYbDVVM0pOUVRoSFFURlZaRVYzUlVJdmQxRkdUVUZOUWtGbU9IZEVaMWxFVmxJd1VFRlJTQzlDUVZGRVFXZEZSMDFCYjBkRFEzRkhVMDAwT1VKQlRVUkJNbWRCVFVkVlEwMVJRMFEyWTBoRlJtdzBZVmhVVVZreVpUTjJPVWQzVDBGRldreDFUaXQ1VW1oSVJrUXZNMjFsYjNsb2NHMTJUM2RuVUZWdVVGZFVlRzVUTkdGMEszRkplRlZEVFVjeGJXbG9SRXN4UVROVlZEZ3lUbEY2TmpCcGJVOXNUVEkzYW1Ka2IxaDBNbEZtZVVaTmJTdFphR2xrUkd0TVJqRjJURlZoWjAwMlFtZEVOVFpMZVV0QlBUMGlYWDAuZXlKMGNtRnVjMkZqZEdsdmJrbGtJam9pTWpBd01EQXdNVEF5Tnpjd01Ua3lPQ0lzSW05eWFXZHBibUZzVkhKaGJuTmhZM1JwYjI1SlpDSTZJakl3TURBd01ERXdNalE1T1RNeU9Ua2lMQ0ozWldKUGNtUmxja3hwYm1WSmRHVnRTV1FpT2lJeU1EQXdNREF3TVRFME1qQXlNVFF3SWl3aVluVnVaR3hsU1dRaU9pSmpiMjB1Ykc5cmFTMXdjbTlxWldOMExteHZhMmt0YldWemMyVnVaMlZ5SWl3aWNISnZaSFZqZEVsa0lqb2lZMjl0TG1kbGRITmxjM05wYjI0dWIzSm5MbkJ5YjE5emRXSWlMQ0p6ZFdKelkzSnBjSFJwYjI1SGNtOTFjRWxrWlc1MGFXWnBaWElpT2lJeU1UYzFNamd4TkNJc0luQjFjbU5vWVhObFJHRjBaU0k2TVRjMU9UY3lOemM1TURBd01Dd2liM0pwWjJsdVlXeFFkWEpqYUdGelpVUmhkR1VpT2pFM05Ua3pNREU0TXpNd01EQXNJbVY0Y0dseVpYTkVZWFJsSWpveE56VTVOekkzT1Rjd01EQXdMQ0p4ZFdGdWRHbDBlU0k2TVN3aWRIbHdaU0k2SWtGMWRHOHRVbVZ1WlhkaFlteGxJRk4xWW5OamNtbHdkR2x2YmlJc0ltbHVRWEJ3VDNkdVpYSnphR2x3Vkhsd1pTSTZJbEJWVWtOSVFWTkZSQ0lzSW5OcFoyNWxaRVJoZEdVaU9qRTNOVGszTWpjNE56WTROemNzSW1WdWRtbHliMjV0Wlc1MElqb2lVMkZ1WkdKdmVDSXNJblJ5WVc1ellXTjBhVzl1VW1WaGMyOXVJam9pVUZWU1EwaEJVMFVpTENKemRHOXlaV1p5YjI1MElqb2lRVlZUSWl3aWMzUnZjbVZtY205dWRFbGtJam9pTVRRek5EWXdJaXdpY0hKcFkyVWlPakU1T1RBc0ltTjFjbkpsYm1ONUlqb2lRVlZFSWl3aVlYQndWSEpoYm5OaFkzUnBiMjVKWkNJNklqY3dORGc1TnpRMk9Ua3dNek00TXpreE9TSjkubWUxWXVvSGFMaExQUWd3RzBvRlc2NzJxbEVCR0NnUVZJTDliWXZ6NkZDc0hUNFI0ZmFHS3BjSDhVNFNjUDAwOG1jNkFIM2p1dGwycldXS2VuR19Nb0EiLCJzaWduZWRSZW5ld2FsSW5mbyI6ImV5SmhiR2NpT2lKRlV6STFOaUlzSW5nMVl5STZXeUpOU1VsRlRWUkRRMEUzWVdkQmQwbENRV2RKVVZJNFMwaDZaRzQxTlRSYUwxVnZjbUZrVG5nNWRIcEJTMEpuWjNGb2EycFBVRkZSUkVGNlFqRk5WVkYzVVdkWlJGWlJVVVJFUkhSQ1kwaENjMXBUUWxoaU0wcHpXa2hrY0ZwSFZXZFNSMVl5V2xkNGRtTkhWbmxKUmtwc1lrZEdNR0ZYT1hWamVVSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlV4TlFXdEhRVEZWUlVOM2QwTlNlbGw0UlhwQlVrSm5UbFpDUVc5TlEydEdkMk5IZUd4SlJXeDFXWGswZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOUWpSWVJGUkpNVTFFYTNoUFZFVTFUa1JSTVUxV2IxaEVWRWt6VFZSQmVFMTZSVE5PUkdONVRURnZkMmRhU1hoUlJFRXJRbWRPVmtKQlRVMU9NVUo1WWpKUloxSlZUa1JKUlRGb1dYbENRbU5JUVdkVk0xSjJZMjFWWjFsWE5XdEpSMnhWWkZjMWJHTjVRbFJrUnpsNVdsTkNVMXBYVG14aFdFSXdTVVpPY0ZveU5YQmliV040VEVSQmNVSm5UbFpDUVhOTlNUQkdkMk5IZUd4SlJtUjJZMjE0YTJReWJHdGFVMEpGV2xoYWJHSkhPWGRhV0VsblZXMVdjMWxZVW5CaU1qVjZUVkpOZDBWUldVUldVVkZMUkVGd1FtTklRbk5hVTBKS1ltMU5kVTFSYzNkRFVWbEVWbEZSUjBWM1NsWlZla0phVFVKTlIwSjVjVWRUVFRRNVFXZEZSME5EY1VkVFRUUTVRWGRGU0VFd1NVRkNUbTVXZG1oamRqZHBWQ3MzUlhnMWRFSk5RbWR5VVhOd1NIcEpjMWhTYVRCWmVHWmxhemRzZGpoM1JXMXFMMkpJYVZkMFRuZEtjV015UW05SWVuTlJhVVZxVURkTFJrbEpTMmMwV1RoNU1DOXVlVzUxUVcxcVoyZEpTVTFKU1VOQ1JFRk5RbWRPVmtoU1RVSkJaamhGUVdwQlFVMUNPRWRCTVZWa1NYZFJXVTFDWVVGR1JEaDJiRU5PVWpBeFJFcHRhV2M1TjJKQ09EVmpLMnhyUjB0YVRVaEJSME5EYzBkQlVWVkdRbmRGUWtKSFVYZFpha0YwUW1kbmNrSm5SVVpDVVdOM1FXOVphR0ZJVWpCalJHOTJUREpPYkdOdVVucE1iVVozWTBkNGJFeHRUblppVXprelpESlNlVnA2V1hWYVIxWjVUVVJGUjBORGMwZEJVVlZHUW5wQlFtaHBWbTlrU0ZKM1QyazRkbUl5VG5walF6Vm9ZMGhDYzFwVE5XcGlNakIyWWpKT2VtTkVRWHBNV0dReldraEtiazVxUVhsTlNVbENTR2RaUkZaU01HZENTVWxDUmxSRFEwRlNSWGRuWjBWT1FtZHZjV2hyYVVjNU1rNXJRbEZaUWsxSlNDdE5TVWhFUW1kbmNrSm5SVVpDVVdORFFXcERRblJuZVVKek1VcHNZa2RzYUdKdFRteEpSemwxU1VoU2IyRllUV2RaTWxaNVpFZHNiV0ZYVG1oa1IxVm5XVzVyWjFsWE5UVkpTRUpvWTI1U05VbEhSbnBqTTFaMFdsaE5aMWxYVG1wYVdFSXdXVmMxYWxwVFFuWmFhVUl3WVVkVloyUkhhR3hpYVVKb1kwaENjMkZYVG1oWmJYaHNTVWhPTUZsWE5XdFpXRXByU1VoU2JHTnRNWHBKUjBaMVdrTkNhbUl5Tld0aFdGSndZakkxZWtsSE9XMUpTRlo2V2xOM1oxa3lWbmxrUjJ4dFlWZE9hR1JIVldkalJ6bHpZVmRPTlVsSFJuVmFRMEpxV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxJUW5sWlYwNHdZVmRPYkVsSVRqQlpXRkpzWWxkV2RXUklUWFZOUkZsSFEwTnpSMEZSVlVaQ2QwbENSbWx3YjJSSVVuZFBhVGgyWkROa00weHRSbmRqUjNoc1RHMU9kbUpUT1dwYVdFb3dZVmRhY0ZreVJqQmFWMFl4WkVkb2RtTnRiREJsVXpoM1NGRlpSRlpTTUU5Q1FsbEZSa2xHYVc5SE5IZE5UVlpCTVd0MU9YcEtiVWRPVUVGV2JqTmxjVTFCTkVkQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlVVSm5iM0ZvYTJsSE9USk9hMEpuYzBKQ1FVbEdRVVJCUzBKblozRm9hMnBQVUZGUlJFRjNUbkJCUkVKdFFXcEZRU3R4V0c1U1JVTTNhRmhKVjFaTWMweDRlbTVxVW5CSmVsQm1OMVpJZWpsV0wwTlViVGdyVEVwc2NsRmxjRzV0WTFCMlIweE9ZMWcyV0ZCdWJHTm5URUZCYWtWQk5VbHFUbHBMWjJjMWNGRTNPV3R1UmpSSllsUllaRXQyT0haMWRFbEVUVmhFYldwUVZsUXpaRWQyUm5SelIxSjNXRTk1ZDFJeWExcERaRk55Wm1WdmRDSXNJazFKU1VSR2FrTkRRWEI1WjBGM1NVSkJaMGxWU1hOSGFGSjNjREJqTW01MlZUUlpVM2xqWVdaUVZHcDZZazVqZDBObldVbExiMXBKZW1vd1JVRjNUWGRhZWtWaVRVSnJSMEV4VlVWQmQzZFRVVmhDZDJKSFZXZFZiVGwyWkVOQ1JGRlRRWFJKUldONlRWTlpkMHBCV1VSV1VWRk1SRUl4UW1OSVFuTmFVMEpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJWUk5Ra1ZIUVRGVlJVTm5kMHRSV0VKM1lrZFZaMU5YTldwTWFrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmQwaG9ZMDVOYWtWM1RYcEZNMDFxUVhwT2VrVjNWMmhqVGsxNldYZE5la1UxVFVSQmQwMUVRWGRYYWtJeFRWVlJkMUZuV1VSV1VWRkVSRVIwUW1OSVFuTmFVMEpZWWpOS2MxcElaSEJhUjFWblVrZFdNbHBYZUhaalIxWjVTVVpLYkdKSFJqQmhWemwxWTNsQ1JGcFlTakJoVjFwd1dUSkdNR0ZYT1hWSlJVWXhaRWRvZG1OdGJEQmxWRVZNVFVGclIwRXhWVVZEZDNkRFVucFplRVY2UVZKQ1owNVdRa0Z2VFVOclJuZGpSM2hzU1VWc2RWbDVOSGhEZWtGS1FtZE9Wa0pCV1ZSQmJGWlVUVWhaZDBWQldVaExiMXBKZW1vd1EwRlJXVVpMTkVWRlFVTkpSRmxuUVVWaWMxRkxRemswVUhKc1YyMWFXRzVZWjNSNGVtUldTa3c0VkRCVFIxbHVaMFJTUjNCdVoyNHpUalpRVkRoS1RVVmlOMFpFYVRSaVFtMVFhRU51V2pNdmMzRTJVRVl2WTBkalMxaFhjMHcxZGs5MFpWSm9lVW8wTlhnelFWTlFOMk5QUWl0aFlXODVNR1pqY0hoVGRpOUZXa1ppYm1sQllrNW5Xa2RvU1dod1NXODBTRFpOU1VnelRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaamhEUVZGQmQwaDNXVVJXVWpCcVFrSm5kMFp2UVZWMU4wUmxiMVpuZW1sS2NXdHBjRzVsZG5JemNuSTVja3hLUzNOM1VtZFpTVXQzV1VKQ1VWVklRVkZGUlU5cVFUUk5SRmxIUTBOelIwRlJWVVpDZWtGQ2FHbHdiMlJJVW5kUGFUaDJZakpPZW1ORE5XaGpTRUp6V2xNMWFtSXlNSFppTWs1NlkwUkJla3hYUm5kalIzaHNZMjA1ZG1SSFRtaGFlazEzVG5kWlJGWlNNR1pDUkVGM1RHcEJjMjlEY1dkTFNWbHRZVWhTTUdORWIzWk1NazU1WWtNMWFHTklRbk5hVXpWcVlqSXdkbGxZUW5kaVIxWjVZakk1TUZreVJtNU5lVFZxWTIxM2QwaFJXVVJXVWpCUFFrSlpSVVpFT0hac1EwNVNNREZFU20xcFp6azNZa0k0TldNcmJHdEhTMXBOUVRSSFFURlZaRVIzUlVJdmQxRkZRWGRKUWtKcVFWRkNaMjl4YUd0cFJ6a3lUbXRDWjBsQ1FrRkpSa0ZFUVV0Q1oyZHhhR3RxVDFCUlVVUkJkMDV2UVVSQ2JFRnFRa0ZZYUZOeE5VbDVTMjluVFVOUWRIYzBPVEJDWVVJMk56ZERZVVZIU2xoMVpsRkNMMFZ4V2tka05rTlRhbWxEZEU5dWRVMVVZbGhXV0cxNGVHTjRabXREVFZGRVZGTlFlR0Z5V2xoMlRuSnJlRlV6Vkd0VlRVa3pNM2w2ZGtaV1ZsSlVOSGQ0VjBwRE9UazBUM05rWTFvMEsxSkhUbk5aUkhsU05XZHRaSEl3YmtSSFp6MGlMQ0pOU1VsRFVYcERRMEZqYldkQmQwbENRV2RKU1V4aldEaHBUa3hHVXpWVmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhkYWVrVmlUVUpyUjBFeFZVVkJkM2RUVVZoQ2QySkhWV2RWYlRsMlpFTkNSRkZUUVhSSlJXTjZUVk5aZDBwQldVUldVVkZNUkVJeFFtTklRbk5hVTBKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVlJOUWtWSFFURlZSVU5uZDB0UldFSjNZa2RWWjFOWE5XcE1ha1ZNVFVGclIwRXhWVVZDYUUxRFZsWk5kMGhvWTA1TlZGRjNUa1JOZDAxVVozaFBWRUV5VjJoalRrMTZhM2RPUkUxM1RWUm5lRTlVUVRKWGFrSnVUVkp6ZDBkUldVUldVVkZFUkVKS1FtTklRbk5hVTBKVFlqSTVNRWxGVGtKSlF6Qm5VbnBOZUVwcVFXdENaMDVXUWtGelRVaFZSbmRqUjNoc1NVVk9iR051VW5CYWJXeHFXVmhTY0dJeU5HZFJXRll3WVVjNWVXRllValZOVWsxM1JWRlpSRlpSVVV0RVFYQkNZMGhDYzFwVFFrcGliVTExVFZGemQwTlJXVVJXVVZGSFJYZEtWbFY2UWpKTlFrRkhRbmx4UjFOTk5EbEJaMFZIUWxOMVFrSkJRV2xCTWtsQlFrcHFjRXg2TVVGamNWUjBhM2xLZVdkU1RXTXpVa05XT0dOWGFsUnVTR05HUW1KYVJIVlhiVUpUY0ROYVNIUm1WR3BxVkhWNGVFVjBXQzh4U0RkWmVWbHNNMG8yV1ZKaVZIcENVRVZXYjBFdlZtaFpSRXRZTVVSNWVFNUNNR05VWkdSeFdHdzFaSFpOVm5wMFN6VXhOMGxFZGxsMVZsUmFXSEJ0YTA5c1JVdE5ZVTVEVFVWQmQwaFJXVVJXVWpCUFFrSlpSVVpNZFhjemNVWlpUVFJwWVhCSmNWb3pjalk1TmpZdllYbDVVM0pOUVRoSFFURlZaRVYzUlVJdmQxRkdUVUZOUWtGbU9IZEVaMWxFVmxJd1VFRlJTQzlDUVZGRVFXZEZSMDFCYjBkRFEzRkhVMDAwT1VKQlRVUkJNbWRCVFVkVlEwMVJRMFEyWTBoRlJtdzBZVmhVVVZreVpUTjJPVWQzVDBGRldreDFUaXQ1VW1oSVJrUXZNMjFsYjNsb2NHMTJUM2RuVUZWdVVGZFVlRzVUTkdGMEszRkplRlZEVFVjeGJXbG9SRXN4UVROVlZEZ3lUbEY2TmpCcGJVOXNUVEkzYW1Ka2IxaDBNbEZtZVVaTmJTdFphR2xrUkd0TVJqRjJURlZoWjAwMlFtZEVOVFpMZVV0QlBUMGlYWDAuZXlKdmNtbG5hVzVoYkZSeVlXNXpZV04wYVc5dVNXUWlPaUl5TURBd01EQXhNREkwT1Rrek1qazVJaXdpWVhWMGIxSmxibVYzVUhKdlpIVmpkRWxrSWpvaVkyOXRMbWRsZEhObGMzTnBiMjR1YjNKbkxuQnliMTl6ZFdJaUxDSndjbTlrZFdOMFNXUWlPaUpqYjIwdVoyVjBjMlZ6YzJsdmJpNXZjbWN1Y0hKdlgzTjFZaUlzSW1GMWRHOVNaVzVsZDFOMFlYUjFjeUk2TUN3aWMybG5ibVZrUkdGMFpTSTZNVGMxT1RjeU56ZzNOamczTnl3aVpXNTJhWEp2Ym0xbGJuUWlPaUpUWVc1a1ltOTRJaXdpY21WalpXNTBVM1ZpYzJOeWFYQjBhVzl1VTNSaGNuUkVZWFJsSWpveE56VTVOekkzTnpjNE1EQXdMQ0p5Wlc1bGQyRnNSR0YwWlNJNk1UYzFPVGN5TnprM01EQXdNQ3dpWVhCd1ZISmhibk5oWTNScGIyNUpaQ0k2SWpjd05EZzVOelEyT1Rrd016TTRNemt4T1NKOS41aUpQZFVJV01YTVRRa3dpcGVSUVZEaHUwZC15a1R1Tnp1aHhLdVBkU2plT0hibk55aTRrWlA5NVJZV21rS3lKMzdEdDlORmtJQlplTW9PVnNqSGhxdyIsInN0YXR1cyI6MX0sInZlcnNpb24iOiIyLjAiLCJzaWduZWREYXRlIjoxNzU5NzI3ODc2ODc3fQ.j1kSeJ6BvHEiVwbe7RyGh90K_wx59pA78qC7N51Svb4X4sdakWc_HM4iM3g0mHJH-RtxLTcRNuD5XApNQzU7Ew"
            }
            ''')

            e06_expire_voluntary: dict[str, base.JSONValue] = json.loads('''
            {
            "signedPayload": "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJub3RpZmljYXRpb25UeXBlIjoiRVhQSVJFRCIsInN1YnR5cGUiOiJWT0xVTlRBUlkiLCJub3RpZmljYXRpb25VVUlEIjoiYWU1ZTY0OTYtNjI2Yi00YzIzLTgyOGYtM2ZhOTE0M2MyZjVlIiwiZGF0YSI6eyJhcHBBcHBsZUlkIjoxNDcwMTY4ODY4LCJidW5kbGVJZCI6ImNvbS5sb2tpLXByb2plY3QubG9raS1tZXNzZW5nZXIiLCJidW5kbGVWZXJzaW9uIjoiNjM3IiwiZW52aXJvbm1lbnQiOiJTYW5kYm94Iiwic2lnbmVkVHJhbnNhY3Rpb25JbmZvIjoiZXlKaGJHY2lPaUpGVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxGVFZSRFEwRTNZV2RCZDBsQ1FXZEpVVkk0UzBoNlpHNDFOVFJhTDFWdmNtRmtUbmc1ZEhwQlMwSm5aM0ZvYTJwUFVGRlJSRUY2UWpGTlZWRjNVV2RaUkZaUlVVUkVSSFJDWTBoQ2MxcFRRbGhpTTBweldraGtjRnBIVldkU1IxWXlXbGQ0ZG1OSFZubEpSa3BzWWtkR01HRlhPWFZqZVVKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVXhOUVd0SFFURlZSVU4zZDBOU2VsbDRSWHBCVWtKblRsWkNRVzlOUTJ0R2QyTkhlR3hKUld4MVdYazBlRU42UVVwQ1owNVdRa0ZaVkVGc1ZsUk5RalJZUkZSSk1VMUVhM2hQVkVVMVRrUlJNVTFXYjFoRVZFa3pUVlJCZUUxNlJUTk9SR041VFRGdmQyZGFTWGhSUkVFclFtZE9Wa0pCVFUxT01VSjVZakpSWjFKVlRrUkpSVEZvV1hsQ1FtTklRV2RWTTFKMlkyMVZaMWxYTld0SlIyeFZaRmMxYkdONVFsUmtSemw1V2xOQ1UxcFhUbXhoV0VJd1NVWk9jRm95TlhCaWJXTjRURVJCY1VKblRsWkNRWE5OU1RCR2QyTkhlR3hKUm1SMlkyMTRhMlF5Ykd0YVUwSkZXbGhhYkdKSE9YZGFXRWxuVlcxV2MxbFlVbkJpTWpWNlRWSk5kMFZSV1VSV1VWRkxSRUZ3UW1OSVFuTmFVMEpLWW0xTmRVMVJjM2REVVZsRVZsRlJSMFYzU2xaVmVrSmFUVUpOUjBKNWNVZFRUVFE1UVdkRlIwTkRjVWRUVFRRNVFYZEZTRUV3U1VGQ1RtNVdkbWhqZGpkcFZDczNSWGcxZEVKTlFtZHlVWE53U0hwSmMxaFNhVEJaZUdabGF6ZHNkamgzUlcxcUwySklhVmQwVG5kS2NXTXlRbTlJZW5OUmFVVnFVRGRMUmtsSlMyYzBXVGg1TUM5dWVXNTFRVzFxWjJkSlNVMUpTVU5DUkVGTlFtZE9Wa2hTVFVKQlpqaEZRV3BCUVUxQ09FZEJNVlZrU1hkUldVMUNZVUZHUkRoMmJFTk9VakF4UkVwdGFXYzVOMkpDT0RWaksyeHJSMHRhVFVoQlIwTkRjMGRCVVZWR1FuZEZRa0pIVVhkWmFrRjBRbWRuY2tKblJVWkNVV04zUVc5WmFHRklVakJqUkc5MlRESk9iR051VW5wTWJVWjNZMGQ0YkV4dFRuWmlVemt6WkRKU2VWcDZXWFZhUjFaNVRVUkZSME5EYzBkQlVWVkdRbnBCUW1ocFZtOWtTRkozVDJrNGRtSXlUbnBqUXpWb1kwaENjMXBUTldwaU1qQjJZakpPZW1ORVFYcE1XR1F6V2toS2JrNXFRWGxOU1VsQ1NHZFpSRlpTTUdkQ1NVbENSbFJEUTBGU1JYZG5aMFZPUW1kdmNXaHJhVWM1TWs1clFsRlpRazFKU0N0TlNVaEVRbWRuY2tKblJVWkNVV05EUVdwRFFuUm5lVUp6TVVwc1lrZHNhR0p0VG14SlJ6bDFTVWhTYjJGWVRXZFpNbFo1WkVkc2JXRlhUbWhrUjFWbldXNXJaMWxYTlRWSlNFSm9ZMjVTTlVsSFJucGpNMVowV2xoTloxbFhUbXBhV0VJd1dWYzFhbHBUUW5aYWFVSXdZVWRWWjJSSGFHeGlhVUpvWTBoQ2MyRlhUbWhaYlhoc1NVaE9NRmxYTld0WldFcHJTVWhTYkdOdE1YcEpSMFoxV2tOQ2FtSXlOV3RoV0ZKd1lqSTFla2xIT1cxSlNGWjZXbE4zWjFreVZubGtSMnh0WVZkT2FHUkhWV2RqUnpsellWZE9OVWxIUm5WYVEwSnFXbGhLTUdGWFduQlpNa1l3WVZjNWRVbElRbmxaVjA0d1lWZE9iRWxJVGpCWldGSnNZbGRXZFdSSVRYVk5SRmxIUTBOelIwRlJWVVpDZDBsQ1JtbHdiMlJJVW5kUGFUaDJaRE5rTTB4dFJuZGpSM2hzVEcxT2RtSlRPV3BhV0Vvd1lWZGFjRmt5UmpCYVYwWXhaRWRvZG1OdGJEQmxVemgzU0ZGWlJGWlNNRTlDUWxsRlJrbEdhVzlITkhkTlRWWkJNV3QxT1hwS2JVZE9VRUZXYmpObGNVMUJORWRCTVZWa1JIZEZRaTkzVVVWQmQwbElaMFJCVVVKbmIzRm9hMmxIT1RKT2EwSm5jMEpDUVVsR1FVUkJTMEpuWjNGb2EycFBVRkZSUkVGM1RuQkJSRUp0UVdwRlFTdHhXRzVTUlVNM2FGaEpWMVpNYzB4NGVtNXFVbkJKZWxCbU4xWkllamxXTDBOVWJUZ3JURXBzY2xGbGNHNXRZMUIyUjB4T1kxZzJXRkJ1YkdOblRFRkJha1ZCTlVscVRscExaMmMxY0ZFM09XdHVSalJKWWxSWVpFdDJPSFoxZEVsRVRWaEViV3BRVmxRelpFZDJSblJ6UjFKM1dFOTVkMUl5YTFwRFpGTnlabVZ2ZENJc0lrMUpTVVJHYWtORFFYQjVaMEYzU1VKQlowbFZTWE5IYUZKM2NEQmpNbTUyVlRSWlUzbGpZV1pRVkdwNllrNWpkME5uV1VsTGIxcEplbW93UlVGM1RYZGFla1ZpVFVKclIwRXhWVVZCZDNkVFVWaENkMkpIVldkVmJUbDJaRU5DUkZGVFFYUkpSV042VFZOWmQwcEJXVVJXVVZGTVJFSXhRbU5JUW5OYVUwSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlZSTlFrVkhRVEZWUlVObmQwdFJXRUozWWtkVloxTlhOV3BNYWtWTVRVRnJSMEV4VlVWQ2FFMURWbFpOZDBob1kwNU5ha1YzVFhwRk0wMXFRWHBPZWtWM1YyaGpUazE2V1hkTmVrVTFUVVJCZDAxRVFYZFhha0l4VFZWUmQxRm5XVVJXVVZGRVJFUjBRbU5JUW5OYVUwSllZak5LYzFwSVpIQmFSMVZuVWtkV01scFhlSFpqUjFaNVNVWktiR0pIUmpCaFZ6bDFZM2xDUkZwWVNqQmhWMXB3V1RKR01HRlhPWFZKUlVZeFpFZG9kbU50YkRCbFZFVk1UVUZyUjBFeFZVVkRkM2REVW5wWmVFVjZRVkpDWjA1V1FrRnZUVU5yUm5kalIzaHNTVVZzZFZsNU5IaERla0ZLUW1kT1ZrSkJXVlJCYkZaVVRVaFpkMFZCV1VoTGIxcEplbW93UTBGUldVWkxORVZGUVVOSlJGbG5RVVZpYzFGTFF6azBVSEpzVjIxYVdHNVlaM1I0ZW1SV1NrdzRWREJUUjFsdVowUlNSM0J1WjI0elRqWlFWRGhLVFVWaU4wWkVhVFJpUW0xUWFFTnVXak12YzNFMlVFWXZZMGRqUzFoWGMwdzFkazkwWlZKb2VVbzBOWGd6UVZOUU4yTlBRaXRoWVc4NU1HWmpjSGhUZGk5RldrWmlibWxCWWs1bldrZG9TV2h3U1c4MFNEWk5TVWd6VFVKSlIwRXhWV1JGZDBWQ0wzZFJTVTFCV1VKQlpqaERRVkZCZDBoM1dVUldVakJxUWtKbmQwWnZRVlYxTjBSbGIxWm5lbWxLY1d0cGNHNWxkbkl6Y25JNWNreEtTM04zVW1kWlNVdDNXVUpDVVZWSVFWRkZSVTlxUVRSTlJGbEhRME56UjBGUlZVWkNla0ZDYUdsd2IyUklVbmRQYVRoMllqSk9lbU5ETldoalNFSnpXbE0xYW1JeU1IWmlNazU2WTBSQmVreFhSbmRqUjNoc1kyMDVkbVJIVG1oYWVrMTNUbmRaUkZaU01HWkNSRUYzVEdwQmMyOURjV2RMU1ZsdFlVaFNNR05FYjNaTU1rNTVZa00xYUdOSVFuTmFVelZxWWpJd2RsbFlRbmRpUjFaNVlqSTVNRmt5Um01TmVUVnFZMjEzZDBoUldVUldVakJQUWtKWlJVWkVPSFpzUTA1U01ERkVTbTFwWnprM1lrSTROV01yYkd0SFMxcE5RVFJIUVRGVlpFUjNSVUl2ZDFGRlFYZEpRa0pxUVZGQ1oyOXhhR3RwUnpreVRtdENaMGxDUWtGSlJrRkVRVXRDWjJkeGFHdHFUMUJSVVVSQmQwNXZRVVJDYkVGcVFrRllhRk54TlVsNVMyOW5UVU5RZEhjME9UQkNZVUkyTnpkRFlVVkhTbGgxWmxGQ0wwVnhXa2RrTmtOVGFtbERkRTl1ZFUxVVlsaFdXRzE0ZUdONFptdERUVkZFVkZOUWVHRnlXbGgyVG5KcmVGVXpWR3RWVFVrek0zbDZka1pXVmxKVU5IZDRWMHBET1RrMFQzTmtZMW8wSzFKSFRuTlpSSGxTTldkdFpISXdia1JIWnowaUxDSk5TVWxEVVhwRFEwRmpiV2RCZDBsQ1FXZEpTVXhqV0RocFRreEdVelZWZDBObldVbExiMXBKZW1vd1JVRjNUWGRhZWtWaVRVSnJSMEV4VlVWQmQzZFRVVmhDZDJKSFZXZFZiVGwyWkVOQ1JGRlRRWFJKUldONlRWTlpkMHBCV1VSV1VWRk1SRUl4UW1OSVFuTmFVMEpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJWUk5Ra1ZIUVRGVlJVTm5kMHRSV0VKM1lrZFZaMU5YTldwTWFrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmQwaG9ZMDVOVkZGM1RrUk5kMDFVWjNoUFZFRXlWMmhqVGsxNmEzZE9SRTEzVFZSbmVFOVVRVEpYYWtKdVRWSnpkMGRSV1VSV1VWRkVSRUpLUW1OSVFuTmFVMEpUWWpJNU1FbEZUa0pKUXpCblVucE5lRXBxUVd0Q1owNVdRa0Z6VFVoVlJuZGpSM2hzU1VWT2JHTnVVbkJhYld4cVdWaFNjR0l5TkdkUldGWXdZVWM1ZVdGWVVqVk5VazEzUlZGWlJGWlJVVXRFUVhCQ1kwaENjMXBUUWtwaWJVMTFUVkZ6ZDBOUldVUldVVkZIUlhkS1ZsVjZRakpOUWtGSFFubHhSMU5OTkRsQlowVkhRbE4xUWtKQlFXbEJNa2xCUWtwcWNFeDZNVUZqY1ZSMGEzbEtlV2RTVFdNelVrTldPR05YYWxSdVNHTkdRbUphUkhWWGJVSlRjRE5hU0hSbVZHcHFWSFY0ZUVWMFdDOHhTRGRaZVZsc00wbzJXVkppVkhwQ1VFVldiMEV2Vm1oWlJFdFlNVVI1ZUU1Q01HTlVaR1J4V0d3MVpIWk5WbnAwU3pVeE4wbEVkbGwxVmxSYVdIQnRhMDlzUlV0TllVNURUVVZCZDBoUldVUldVakJQUWtKWlJVWk1kWGN6Y1VaWlRUUnBZWEJKY1ZvemNqWTVOall2WVhsNVUzSk5RVGhIUVRGVlpFVjNSVUl2ZDFGR1RVRk5Ra0ZtT0hkRVoxbEVWbEl3VUVGUlNDOUNRVkZFUVdkRlIwMUJiMGREUTNGSFUwMDBPVUpCVFVSQk1tZEJUVWRWUTAxUlEwUTJZMGhGUm13MFlWaFVVVmt5WlROMk9VZDNUMEZGV2t4MVRpdDVVbWhJUmtRdk0yMWxiM2xvY0cxMlQzZG5VRlZ1VUZkVWVHNVROR0YwSzNGSmVGVkRUVWN4Yldsb1JFc3hRVE5WVkRneVRsRjZOakJwYlU5c1RUSTNhbUprYjFoME1sRm1lVVpOYlN0WmFHbGtSR3RNUmpGMlRGVmhaMDAyUW1kRU5UWkxlVXRCUFQwaVhYMC5leUowY21GdWMyRmpkR2x2Ymtsa0lqb2lNakF3TURBd01UQXlOemN3TVRreU9DSXNJbTl5YVdkcGJtRnNWSEpoYm5OaFkzUnBiMjVKWkNJNklqSXdNREF3TURFd01qUTVPVE15T1RraUxDSjNaV0pQY21SbGNreHBibVZKZEdWdFNXUWlPaUl5TURBd01EQXdNVEUwTWpBeU1UUXdJaXdpWW5WdVpHeGxTV1FpT2lKamIyMHViRzlyYVMxd2NtOXFaV04wTG14dmEya3RiV1Z6YzJWdVoyVnlJaXdpY0hKdlpIVmpkRWxrSWpvaVkyOXRMbWRsZEhObGMzTnBiMjR1YjNKbkxuQnliMTl6ZFdJaUxDSnpkV0p6WTNKcGNIUnBiMjVIY205MWNFbGtaVzUwYVdacFpYSWlPaUl5TVRjMU1qZ3hOQ0lzSW5CMWNtTm9ZWE5sUkdGMFpTSTZNVGMxT1RjeU56YzVNREF3TUN3aWIzSnBaMmx1WVd4UWRYSmphR0Z6WlVSaGRHVWlPakUzTlRrek1ERTRNek13TURBc0ltVjRjR2x5WlhORVlYUmxJam94TnpVNU56STNPVGN3TURBd0xDSnhkV0Z1ZEdsMGVTSTZNU3dpZEhsd1pTSTZJa0YxZEc4dFVtVnVaWGRoWW14bElGTjFZbk5qY21sd2RHbHZiaUlzSW1sdVFYQndUM2R1WlhKemFHbHdWSGx3WlNJNklsQlZVa05JUVZORlJDSXNJbk5wWjI1bFpFUmhkR1VpT2pFM05UazNNamM1T0RVM09Ua3NJbVZ1ZG1seWIyNXRaVzUwSWpvaVUyRnVaR0p2ZUNJc0luUnlZVzV6WVdOMGFXOXVVbVZoYzI5dUlqb2lVRlZTUTBoQlUwVWlMQ0p6ZEc5eVpXWnliMjUwSWpvaVFWVlRJaXdpYzNSdmNtVm1jbTl1ZEVsa0lqb2lNVFF6TkRZd0lpd2ljSEpwWTJVaU9qRTVPVEFzSW1OMWNuSmxibU41SWpvaVFWVkVJaXdpWVhCd1ZISmhibk5oWTNScGIyNUpaQ0k2SWpjd05EZzVOelEyT1Rrd016TTRNemt4T1NKOS55U3l1WF84ekVaTkM3Q3NqZWItaU5ZRUk0eHJwT2tYX3VJaUlCYkxmS2FBdFJNa1VkXzhIaE5nS182bXFoQy1ZUnlpczBBR3IzSnFVcURjaEJwaXRGZyIsInNpZ25lZFJlbmV3YWxJbmZvIjoiZXlKaGJHY2lPaUpGVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxGVFZSRFEwRTNZV2RCZDBsQ1FXZEpVVkk0UzBoNlpHNDFOVFJhTDFWdmNtRmtUbmc1ZEhwQlMwSm5aM0ZvYTJwUFVGRlJSRUY2UWpGTlZWRjNVV2RaUkZaUlVVUkVSSFJDWTBoQ2MxcFRRbGhpTTBweldraGtjRnBIVldkU1IxWXlXbGQ0ZG1OSFZubEpSa3BzWWtkR01HRlhPWFZqZVVKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVXhOUVd0SFFURlZSVU4zZDBOU2VsbDRSWHBCVWtKblRsWkNRVzlOUTJ0R2QyTkhlR3hKUld4MVdYazBlRU42UVVwQ1owNVdRa0ZaVkVGc1ZsUk5RalJZUkZSSk1VMUVhM2hQVkVVMVRrUlJNVTFXYjFoRVZFa3pUVlJCZUUxNlJUTk9SR041VFRGdmQyZGFTWGhSUkVFclFtZE9Wa0pCVFUxT01VSjVZakpSWjFKVlRrUkpSVEZvV1hsQ1FtTklRV2RWTTFKMlkyMVZaMWxYTld0SlIyeFZaRmMxYkdONVFsUmtSemw1V2xOQ1UxcFhUbXhoV0VJd1NVWk9jRm95TlhCaWJXTjRURVJCY1VKblRsWkNRWE5OU1RCR2QyTkhlR3hKUm1SMlkyMTRhMlF5Ykd0YVUwSkZXbGhhYkdKSE9YZGFXRWxuVlcxV2MxbFlVbkJpTWpWNlRWSk5kMFZSV1VSV1VWRkxSRUZ3UW1OSVFuTmFVMEpLWW0xTmRVMVJjM2REVVZsRVZsRlJSMFYzU2xaVmVrSmFUVUpOUjBKNWNVZFRUVFE1UVdkRlIwTkRjVWRUVFRRNVFYZEZTRUV3U1VGQ1RtNVdkbWhqZGpkcFZDczNSWGcxZEVKTlFtZHlVWE53U0hwSmMxaFNhVEJaZUdabGF6ZHNkamgzUlcxcUwySklhVmQwVG5kS2NXTXlRbTlJZW5OUmFVVnFVRGRMUmtsSlMyYzBXVGg1TUM5dWVXNTFRVzFxWjJkSlNVMUpTVU5DUkVGTlFtZE9Wa2hTVFVKQlpqaEZRV3BCUVUxQ09FZEJNVlZrU1hkUldVMUNZVUZHUkRoMmJFTk9VakF4UkVwdGFXYzVOMkpDT0RWaksyeHJSMHRhVFVoQlIwTkRjMGRCVVZWR1FuZEZRa0pIVVhkWmFrRjBRbWRuY2tKblJVWkNVV04zUVc5WmFHRklVakJqUkc5MlRESk9iR051VW5wTWJVWjNZMGQ0YkV4dFRuWmlVemt6WkRKU2VWcDZXWFZhUjFaNVRVUkZSME5EYzBkQlVWVkdRbnBCUW1ocFZtOWtTRkozVDJrNGRtSXlUbnBqUXpWb1kwaENjMXBUTldwaU1qQjJZakpPZW1ORVFYcE1XR1F6V2toS2JrNXFRWGxOU1VsQ1NHZFpSRlpTTUdkQ1NVbENSbFJEUTBGU1JYZG5aMFZPUW1kdmNXaHJhVWM1TWs1clFsRlpRazFKU0N0TlNVaEVRbWRuY2tKblJVWkNVV05EUVdwRFFuUm5lVUp6TVVwc1lrZHNhR0p0VG14SlJ6bDFTVWhTYjJGWVRXZFpNbFo1WkVkc2JXRlhUbWhrUjFWbldXNXJaMWxYTlRWSlNFSm9ZMjVTTlVsSFJucGpNMVowV2xoTloxbFhUbXBhV0VJd1dWYzFhbHBUUW5aYWFVSXdZVWRWWjJSSGFHeGlhVUpvWTBoQ2MyRlhUbWhaYlhoc1NVaE9NRmxYTld0WldFcHJTVWhTYkdOdE1YcEpSMFoxV2tOQ2FtSXlOV3RoV0ZKd1lqSTFla2xIT1cxSlNGWjZXbE4zWjFreVZubGtSMnh0WVZkT2FHUkhWV2RqUnpsellWZE9OVWxIUm5WYVEwSnFXbGhLTUdGWFduQlpNa1l3WVZjNWRVbElRbmxaVjA0d1lWZE9iRWxJVGpCWldGSnNZbGRXZFdSSVRYVk5SRmxIUTBOelIwRlJWVVpDZDBsQ1JtbHdiMlJJVW5kUGFUaDJaRE5rTTB4dFJuZGpSM2hzVEcxT2RtSlRPV3BhV0Vvd1lWZGFjRmt5UmpCYVYwWXhaRWRvZG1OdGJEQmxVemgzU0ZGWlJGWlNNRTlDUWxsRlJrbEdhVzlITkhkTlRWWkJNV3QxT1hwS2JVZE9VRUZXYmpObGNVMUJORWRCTVZWa1JIZEZRaTkzVVVWQmQwbElaMFJCVVVKbmIzRm9hMmxIT1RKT2EwSm5jMEpDUVVsR1FVUkJTMEpuWjNGb2EycFBVRkZSUkVGM1RuQkJSRUp0UVdwRlFTdHhXRzVTUlVNM2FGaEpWMVpNYzB4NGVtNXFVbkJKZWxCbU4xWkllamxXTDBOVWJUZ3JURXBzY2xGbGNHNXRZMUIyUjB4T1kxZzJXRkJ1YkdOblRFRkJha1ZCTlVscVRscExaMmMxY0ZFM09XdHVSalJKWWxSWVpFdDJPSFoxZEVsRVRWaEViV3BRVmxRelpFZDJSblJ6UjFKM1dFOTVkMUl5YTFwRFpGTnlabVZ2ZENJc0lrMUpTVVJHYWtORFFYQjVaMEYzU1VKQlowbFZTWE5IYUZKM2NEQmpNbTUyVlRSWlUzbGpZV1pRVkdwNllrNWpkME5uV1VsTGIxcEplbW93UlVGM1RYZGFla1ZpVFVKclIwRXhWVVZCZDNkVFVWaENkMkpIVldkVmJUbDJaRU5DUkZGVFFYUkpSV042VFZOWmQwcEJXVVJXVVZGTVJFSXhRbU5JUW5OYVUwSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlZSTlFrVkhRVEZWUlVObmQwdFJXRUozWWtkVloxTlhOV3BNYWtWTVRVRnJSMEV4VlVWQ2FFMURWbFpOZDBob1kwNU5ha1YzVFhwRk0wMXFRWHBPZWtWM1YyaGpUazE2V1hkTmVrVTFUVVJCZDAxRVFYZFhha0l4VFZWUmQxRm5XVVJXVVZGRVJFUjBRbU5JUW5OYVUwSllZak5LYzFwSVpIQmFSMVZuVWtkV01scFhlSFpqUjFaNVNVWktiR0pIUmpCaFZ6bDFZM2xDUkZwWVNqQmhWMXB3V1RKR01HRlhPWFZKUlVZeFpFZG9kbU50YkRCbFZFVk1UVUZyUjBFeFZVVkRkM2REVW5wWmVFVjZRVkpDWjA1V1FrRnZUVU5yUm5kalIzaHNTVVZzZFZsNU5IaERla0ZLUW1kT1ZrSkJXVlJCYkZaVVRVaFpkMFZCV1VoTGIxcEplbW93UTBGUldVWkxORVZGUVVOSlJGbG5RVVZpYzFGTFF6azBVSEpzVjIxYVdHNVlaM1I0ZW1SV1NrdzRWREJUUjFsdVowUlNSM0J1WjI0elRqWlFWRGhLVFVWaU4wWkVhVFJpUW0xUWFFTnVXak12YzNFMlVFWXZZMGRqUzFoWGMwdzFkazkwWlZKb2VVbzBOWGd6UVZOUU4yTlBRaXRoWVc4NU1HWmpjSGhUZGk5RldrWmlibWxCWWs1bldrZG9TV2h3U1c4MFNEWk5TVWd6VFVKSlIwRXhWV1JGZDBWQ0wzZFJTVTFCV1VKQlpqaERRVkZCZDBoM1dVUldVakJxUWtKbmQwWnZRVlYxTjBSbGIxWm5lbWxLY1d0cGNHNWxkbkl6Y25JNWNreEtTM04zVW1kWlNVdDNXVUpDVVZWSVFWRkZSVTlxUVRSTlJGbEhRME56UjBGUlZVWkNla0ZDYUdsd2IyUklVbmRQYVRoMllqSk9lbU5ETldoalNFSnpXbE0xYW1JeU1IWmlNazU2WTBSQmVreFhSbmRqUjNoc1kyMDVkbVJIVG1oYWVrMTNUbmRaUkZaU01HWkNSRUYzVEdwQmMyOURjV2RMU1ZsdFlVaFNNR05FYjNaTU1rNTVZa00xYUdOSVFuTmFVelZxWWpJd2RsbFlRbmRpUjFaNVlqSTVNRmt5Um01TmVUVnFZMjEzZDBoUldVUldVakJQUWtKWlJVWkVPSFpzUTA1U01ERkVTbTFwWnprM1lrSTROV01yYkd0SFMxcE5RVFJIUVRGVlpFUjNSVUl2ZDFGRlFYZEpRa0pxUVZGQ1oyOXhhR3RwUnpreVRtdENaMGxDUWtGSlJrRkVRVXRDWjJkeGFHdHFUMUJSVVVSQmQwNXZRVVJDYkVGcVFrRllhRk54TlVsNVMyOW5UVU5RZEhjME9UQkNZVUkyTnpkRFlVVkhTbGgxWmxGQ0wwVnhXa2RrTmtOVGFtbERkRTl1ZFUxVVlsaFdXRzE0ZUdONFptdERUVkZFVkZOUWVHRnlXbGgyVG5KcmVGVXpWR3RWVFVrek0zbDZka1pXVmxKVU5IZDRWMHBET1RrMFQzTmtZMW8wSzFKSFRuTlpSSGxTTldkdFpISXdia1JIWnowaUxDSk5TVWxEVVhwRFEwRmpiV2RCZDBsQ1FXZEpTVXhqV0RocFRreEdVelZWZDBObldVbExiMXBKZW1vd1JVRjNUWGRhZWtWaVRVSnJSMEV4VlVWQmQzZFRVVmhDZDJKSFZXZFZiVGwyWkVOQ1JGRlRRWFJKUldONlRWTlpkMHBCV1VSV1VWRk1SRUl4UW1OSVFuTmFVMEpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJWUk5Ra1ZIUVRGVlJVTm5kMHRSV0VKM1lrZFZaMU5YTldwTWFrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmQwaG9ZMDVOVkZGM1RrUk5kMDFVWjNoUFZFRXlWMmhqVGsxNmEzZE9SRTEzVFZSbmVFOVVRVEpYYWtKdVRWSnpkMGRSV1VSV1VWRkVSRUpLUW1OSVFuTmFVMEpUWWpJNU1FbEZUa0pKUXpCblVucE5lRXBxUVd0Q1owNVdRa0Z6VFVoVlJuZGpSM2hzU1VWT2JHTnVVbkJhYld4cVdWaFNjR0l5TkdkUldGWXdZVWM1ZVdGWVVqVk5VazEzUlZGWlJGWlJVVXRFUVhCQ1kwaENjMXBUUWtwaWJVMTFUVkZ6ZDBOUldVUldVVkZIUlhkS1ZsVjZRakpOUWtGSFFubHhSMU5OTkRsQlowVkhRbE4xUWtKQlFXbEJNa2xCUWtwcWNFeDZNVUZqY1ZSMGEzbEtlV2RTVFdNelVrTldPR05YYWxSdVNHTkdRbUphUkhWWGJVSlRjRE5hU0hSbVZHcHFWSFY0ZUVWMFdDOHhTRGRaZVZsc00wbzJXVkppVkhwQ1VFVldiMEV2Vm1oWlJFdFlNVVI1ZUU1Q01HTlVaR1J4V0d3MVpIWk5WbnAwU3pVeE4wbEVkbGwxVmxSYVdIQnRhMDlzUlV0TllVNURUVVZCZDBoUldVUldVakJQUWtKWlJVWk1kWGN6Y1VaWlRUUnBZWEJKY1ZvemNqWTVOall2WVhsNVUzSk5RVGhIUVRGVlpFVjNSVUl2ZDFGR1RVRk5Ra0ZtT0hkRVoxbEVWbEl3VUVGUlNDOUNRVkZFUVdkRlIwMUJiMGREUTNGSFUwMDBPVUpCVFVSQk1tZEJUVWRWUTAxUlEwUTJZMGhGUm13MFlWaFVVVmt5WlROMk9VZDNUMEZGV2t4MVRpdDVVbWhJUmtRdk0yMWxiM2xvY0cxMlQzZG5VRlZ1VUZkVWVHNVROR0YwSzNGSmVGVkRUVWN4Yldsb1JFc3hRVE5WVkRneVRsRjZOakJwYlU5c1RUSTNhbUprYjFoME1sRm1lVVpOYlN0WmFHbGtSR3RNUmpGMlRGVmhaMDAyUW1kRU5UWkxlVXRCUFQwaVhYMC5leUpsZUhCcGNtRjBhVzl1U1c1MFpXNTBJam94TENKdmNtbG5hVzVoYkZSeVlXNXpZV04wYVc5dVNXUWlPaUl5TURBd01EQXhNREkwT1Rrek1qazVJaXdpWVhWMGIxSmxibVYzVUhKdlpIVmpkRWxrSWpvaVkyOXRMbWRsZEhObGMzTnBiMjR1YjNKbkxuQnliMTl6ZFdJaUxDSndjbTlrZFdOMFNXUWlPaUpqYjIwdVoyVjBjMlZ6YzJsdmJpNXZjbWN1Y0hKdlgzTjFZaUlzSW1GMWRHOVNaVzVsZDFOMFlYUjFjeUk2TUN3aWFYTkpia0pwYkd4cGJtZFNaWFJ5ZVZCbGNtbHZaQ0k2Wm1Gc2MyVXNJbk5wWjI1bFpFUmhkR1VpT2pFM05UazNNamM1T0RVM09Ua3NJbVZ1ZG1seWIyNXRaVzUwSWpvaVUyRnVaR0p2ZUNJc0luSmxZMlZ1ZEZOMVluTmpjbWx3ZEdsdmJsTjBZWEowUkdGMFpTSTZNVGMxT1RjeU56YzNPREF3TUN3aWNtVnVaWGRoYkVSaGRHVWlPakUzTlRrM01qYzVOekF3TURBc0ltRndjRlJ5WVc1ellXTjBhVzl1U1dRaU9pSTNNRFE0T1RjME5qazVNRE16T0RNNU1Ua2lmUS5WWVNHVW5IOUpYLUJVdktFUkFJQ0tGX0JUSUF5Qm1ad1hhTHNqaDFqRlJuZnVhdWxhUDlGa19qVzRUVXViVmZ3Tng1NEk2bENGbmRRa2IwTGVyUFhpZyIsInN0YXR1cyI6Mn0sInZlcnNpb24iOiIyLjAiLCJzaWduZWREYXRlIjoxNzU5NzI3OTg1Nzk5fQ.CA3VKbBmm6DUKas3RqS9eIoiPkILKj-jicL2TOxmY-Q0EkPOwMA-y-sa50uxUPwNzQlX8mFylRMieRzQ7Fep3g"
            }
            ''')

            e00_sub_to_3_months_signed_payload:              str = typing.cast(str, e00_sub_to_3_months['signedPayload'])
            e01_upgrade_to_1wk_signed_payload:               str = typing.cast(str, e01_upgrade_to_1wk['signedPayload'])
            e02_disable_auto_renew_signed_payload:           str = typing.cast(str, e02_disable_auto_renew['signedPayload'])
            e03_queue_downgrade_to_3_months_signed_payload:  str = typing.cast(str, e03_queue_downgrade_to_3_months['signedPayload'])
            e04_cancel_downgrade_to_3_months_signed_payload: str = typing.cast(str, e04_cancel_downgrade_to_3_months['signedPayload'])
            e05_disable_auto_renew_signed_payload:           str = typing.cast(str, e05_disable_auto_renew['signedPayload'])
            e06_expire_voluntary_signed_payload:             str = typing.cast(str, e06_expire_voluntary['signedPayload'])

            core: platform_apple.Core = platform_apple.init()

            e00_sub_to_3_months_decoded_body:              AppleResponseBodyV2DecodedPayload = core.signed_data_verifier.verify_and_decode_notification(e00_sub_to_3_months_signed_payload)
            e01_upgrade_to_1wk_decoded_body:               AppleResponseBodyV2DecodedPayload = core.signed_data_verifier.verify_and_decode_notification(e01_upgrade_to_1wk_signed_payload)
            e02_disable_auto_renew_decoded_body:           AppleResponseBodyV2DecodedPayload = core.signed_data_verifier.verify_and_decode_notification(e02_disable_auto_renew_signed_payload)
            e03_queue_downgrade_to_3_months_decoded_body:  AppleResponseBodyV2DecodedPayload = core.signed_data_verifier.verify_and_decode_notification(e03_queue_downgrade_to_3_months_signed_payload)
            e04_cancel_downgrade_to_3_months_decoded_body: AppleResponseBodyV2DecodedPayload = core.signed_data_verifier.verify_and_decode_notification(e04_cancel_downgrade_to_3_months_signed_payload)
            e05_disable_auto_renew_decoded_body:           AppleResponseBodyV2DecodedPayload = core.signed_data_verifier.verify_and_decode_notification(e05_disable_auto_renew_signed_payload)
            e06_expire_voluntary_decoded_body:             AppleResponseBodyV2DecodedPayload = core.signed_data_verifier.verify_and_decode_notification(e06_expire_voluntary_signed_payload)

            dump_apple_signed_payloads(core, e00_sub_to_3_months_decoded_body,              'e00_sub_to_3_months_')
            dump_apple_signed_payloads(core, e01_upgrade_to_1wk_decoded_body,               'e01_upgrade_to_1wk_')
            dump_apple_signed_payloads(core, e02_disable_auto_renew_decoded_body,           'e02_disable_auto_renew_')
            dump_apple_signed_payloads(core, e03_queue_downgrade_to_3_months_decoded_body,  'e03_queue_downgrade_to_3_months_')
            dump_apple_signed_payloads(core, e04_cancel_downgrade_to_3_months_decoded_body, 'e04_cancel_downgrade_to_3_months_')
            dump_apple_signed_payloads(core, e05_disable_auto_renew_decoded_body,           'e05_disable_auto_renew_')
            dump_apple_signed_payloads(core, e06_expire_voluntary_decoded_body,             'e06_expire_voluntary_')

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        e00_sub_to_3_months_body                                             = AppleResponseBodyV2DecodedPayload()
        e00_sub_to_3_months_body_data                                        = AppleData()
        e00_sub_to_3_months_body_data.appAppleId                             = 1470168868
        e00_sub_to_3_months_body_data.bundleId                               = 'com.loki-project.loki-messenger'
        e00_sub_to_3_months_body_data.bundleVersion                          = '637'
        e00_sub_to_3_months_body_data.consumptionRequestReason               = None
        e00_sub_to_3_months_body_data.environment                            = AppleEnvironment.SANDBOX
        e00_sub_to_3_months_body_data.rawConsumptionRequestReason            = None
        e00_sub_to_3_months_body_data.rawEnvironment                         = 'Sandbox'
        e00_sub_to_3_months_body_data.rawStatus                              = 1
        e00_sub_to_3_months_body_data.signedRenewalInfo                      = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWJfM19tb250aHMiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1Yl8zX21vbnRocyIsImF1dG9SZW5ld1N0YXR1cyI6MSwicmVuZXdhbFByaWNlIjo1OTkwLCJjdXJyZW5jeSI6IkFVRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc3ODU0NDUsImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc1OTcyNzc3ODAwMCwicmVuZXdhbERhdGUiOjE3NTk3MjgzMTgwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.s3yvWeyKDVbZSciqRVRpMBGkpNnQ10lEn-6jXL9yPK-Yi-nEkXOLIzl4Ji5VutI-2kY2vZlxj7mVXu-2v3Mi0Q'
        e00_sub_to_3_months_body_data.signedTransactionInfo                  = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNzcwMTg5OCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTEzODY0NjA1IiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWJfM19tb250aHMiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTcyNzc3ODAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5NzI4MzE4MDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc3ODU0NDUsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjU5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.bMfO0cWYCajFTg5Mmv2nyU_lBQfyPM9Z5pOw_B6jO9jy1qxc49DffTVf_ZOU5HH-04W7t3qczVi8KkLeWNbi_A'
        e00_sub_to_3_months_body_data.status                                 = AppleStatus.ACTIVE
        e00_sub_to_3_months_body.data                                        = e00_sub_to_3_months_body_data
        e00_sub_to_3_months_body.externalPurchaseToken                       = None
        e00_sub_to_3_months_body.notificationType                            = AppleNotificationTypeV2.SUBSCRIBED
        e00_sub_to_3_months_body.notificationUUID                            = 'fee6ade6-5871-4e0f-9d2e-5d6229a24027'
        e00_sub_to_3_months_body.rawNotificationType                         = 'SUBSCRIBED'
        e00_sub_to_3_months_body.rawSubtype                                  = 'RESUBSCRIBE'
        e00_sub_to_3_months_body.signedDate                                  = 1759727785445
        e00_sub_to_3_months_body.subtype                                     = AppleSubtype.RESUBSCRIBE
        e00_sub_to_3_months_body.summary                                     = None
        e00_sub_to_3_months_body.version                                     = '2.0'

        # NOTE: Signed Renewal Info
        e00_sub_to_3_months_renewal_info                                     = AppleJWSRenewalInfoDecodedPayload()
        e00_sub_to_3_months_renewal_info.appAccountToken                     = None
        e00_sub_to_3_months_renewal_info.appTransactionId                    = '704897469903383919'
        e00_sub_to_3_months_renewal_info.autoRenewProductId                  = None
        e00_sub_to_3_months_renewal_info.autoRenewStatus                     = None
        e00_sub_to_3_months_renewal_info.currency                            = 'AUD'
        e00_sub_to_3_months_renewal_info.eligibleWinBackOfferIds             = None
        e00_sub_to_3_months_renewal_info.environment                         = AppleEnvironment.SANDBOX
        e00_sub_to_3_months_renewal_info.expirationIntent                    = None
        e00_sub_to_3_months_renewal_info.gracePeriodExpiresDate              = None
        e00_sub_to_3_months_renewal_info.isInBillingRetryPeriod              = None
        e00_sub_to_3_months_renewal_info.offerDiscountType                   = None
        e00_sub_to_3_months_renewal_info.offerIdentifier                     = None
        e00_sub_to_3_months_renewal_info.offerPeriod                         = None
        e00_sub_to_3_months_renewal_info.offerType                           = None
        e00_sub_to_3_months_renewal_info.originalTransactionId               = '2000001024993299'
        e00_sub_to_3_months_renewal_info.priceIncreaseStatus                 = None
        e00_sub_to_3_months_renewal_info.productId                           = 'com.getsession.org.pro_sub_3_months'
        e00_sub_to_3_months_renewal_info.rawAutoRenewStatus                  = None
        e00_sub_to_3_months_renewal_info.rawEnvironment                      = 'Sandbox'
        e00_sub_to_3_months_renewal_info.rawExpirationIntent                 = None
        e00_sub_to_3_months_renewal_info.rawOfferDiscountType                = None
        e00_sub_to_3_months_renewal_info.rawOfferType                        = None
        e00_sub_to_3_months_renewal_info.rawPriceIncreaseStatus              = None
        e00_sub_to_3_months_renewal_info.recentSubscriptionStartDate         = None
        e00_sub_to_3_months_renewal_info.renewalDate                         = None
        e00_sub_to_3_months_renewal_info.renewalPrice                        = None
        e00_sub_to_3_months_renewal_info.signedDate                          = 1759727785445

        # NOTE: Signed Transaction Info
        e00_sub_to_3_months_tx_info                                          = AppleJWSTransactionDecodedPayload()
        e00_sub_to_3_months_tx_info.appAccountToken                          = None
        e00_sub_to_3_months_tx_info.appTransactionId                         = '704897469903383919'
        e00_sub_to_3_months_tx_info.bundleId                                 = 'com.loki-project.loki-messenger'
        e00_sub_to_3_months_tx_info.currency                                 = 'AUD'
        e00_sub_to_3_months_tx_info.environment                              = AppleEnvironment.SANDBOX
        e00_sub_to_3_months_tx_info.expiresDate                              = 1759728318000
        e00_sub_to_3_months_tx_info.inAppOwnershipType                       = AppleInAppOwnershipType.PURCHASED
        e00_sub_to_3_months_tx_info.isUpgraded                               = None
        e00_sub_to_3_months_tx_info.offerDiscountType                        = None
        e00_sub_to_3_months_tx_info.offerIdentifier                          = None
        e00_sub_to_3_months_tx_info.offerPeriod                              = None
        e00_sub_to_3_months_tx_info.offerType                                = None
        e00_sub_to_3_months_tx_info.originalPurchaseDate                     = 1759301833000
        e00_sub_to_3_months_tx_info.originalTransactionId                    = '2000001024993299'
        e00_sub_to_3_months_tx_info.price                                    = 5990
        e00_sub_to_3_months_tx_info.productId                                = 'com.getsession.org.pro_sub_3_months'
        e00_sub_to_3_months_tx_info.purchaseDate                             = 1759727778000
        e00_sub_to_3_months_tx_info.quantity                                 = 1
        e00_sub_to_3_months_tx_info.rawEnvironment                           = 'Sandbox'
        e00_sub_to_3_months_tx_info.rawInAppOwnershipType                    = 'PURCHASED'
        e00_sub_to_3_months_tx_info.rawOfferDiscountType                     = None
        e00_sub_to_3_months_tx_info.rawOfferType                             = None
        e00_sub_to_3_months_tx_info.rawRevocationReason                      = None
        e00_sub_to_3_months_tx_info.rawTransactionReason                     = 'PURCHASE'
        e00_sub_to_3_months_tx_info.rawType                                  = 'Auto-Renewable Subscription'
        e00_sub_to_3_months_tx_info.revocationDate                           = None
        e00_sub_to_3_months_tx_info.revocationReason                         = None
        e00_sub_to_3_months_tx_info.signedDate                               = 1759727785445
        e00_sub_to_3_months_tx_info.storefront                               = 'AUS'
        e00_sub_to_3_months_tx_info.storefrontId                             = '143460'
        e00_sub_to_3_months_tx_info.subscriptionGroupIdentifier              = '21752814'
        e00_sub_to_3_months_tx_info.transactionId                            = '2000001027701898'
        e00_sub_to_3_months_tx_info.transactionReason                        = AppleTransactionReason.PURCHASE
        e00_sub_to_3_months_tx_info.type                                     = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        e00_sub_to_3_months_tx_info.webOrderLineItemId                       = '2000000113864605'

        e00_sub_to_3_months_decoded_notification                             = platform_apple.DecodedNotification(body=e00_sub_to_3_months_body, tx_info=e00_sub_to_3_months_tx_info, renewal_info=e00_sub_to_3_months_renewal_info)

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        e01_upgrade_to_1wk_body                                     = AppleResponseBodyV2DecodedPayload()
        e01_upgrade_to_1wk_body_data                                = AppleData()
        e01_upgrade_to_1wk_body_data.appAppleId                     = 1470168868
        e01_upgrade_to_1wk_body_data.bundleId                       = 'com.loki-project.loki-messenger'
        e01_upgrade_to_1wk_body_data.bundleVersion                  = '637'
        e01_upgrade_to_1wk_body_data.consumptionRequestReason       = None
        e01_upgrade_to_1wk_body_data.environment                    = AppleEnvironment.SANDBOX
        e01_upgrade_to_1wk_body_data.rawConsumptionRequestReason    = None
        e01_upgrade_to_1wk_body_data.rawEnvironment                 = 'Sandbox'
        e01_upgrade_to_1wk_body_data.rawStatus                      = 1
        e01_upgrade_to_1wk_body_data.signedRenewalInfo              = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MSwicmVuZXdhbFByaWNlIjoxOTkwLCJjdXJyZW5jeSI6IkFVRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc3OTk4MTAsImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc1OTcyNzc3ODAwMCwicmVuZXdhbERhdGUiOjE3NTk3Mjc5NzAwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.-iX0StcW4lxx8zCskl1SFf-HNOV5KiwddKJ42XmWaFCsEuABtAWszBEsJu4OIQTHh6aamYx5CkoBTeUy6hsRtg'
        e01_upgrade_to_1wk_body_data.signedTransactionInfo          = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNzcwMTkyOCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTE0MjAyMTQwIiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTcyNzc5MDAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5NzI3OTcwMDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc3OTk4MTAsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.PHyVvDlmjoO3KFj9U_JsA7pxIp730GIwIskog5Pfsrcb_HZpXcU1LUOZYkQJjtfVPyfunMpIJAuomhfcXiGk1g'
        e01_upgrade_to_1wk_body_data.status                         = AppleStatus.ACTIVE
        e01_upgrade_to_1wk_body.data                                = e01_upgrade_to_1wk_body_data
        e01_upgrade_to_1wk_body.externalPurchaseToken               = None
        e01_upgrade_to_1wk_body.notificationType                    = AppleNotificationTypeV2.DID_CHANGE_RENEWAL_PREF
        e01_upgrade_to_1wk_body.notificationUUID                    = 'a3a3b7ae-3bd8-4b98-a83d-e5f4380aeaa2'
        e01_upgrade_to_1wk_body.rawNotificationType                 = 'DID_CHANGE_RENEWAL_PREF'
        e01_upgrade_to_1wk_body.rawSubtype                          = 'UPGRADE'
        e01_upgrade_to_1wk_body.signedDate                          = 1759727799810
        e01_upgrade_to_1wk_body.subtype                             = AppleSubtype.UPGRADE
        e01_upgrade_to_1wk_body.summary                             = None
        e01_upgrade_to_1wk_body.version                             = '2.0'

        # NOTE: Signed Renewal Info
        e01_upgrade_to_1wk_renewal_info                             = AppleJWSRenewalInfoDecodedPayload()
        e01_upgrade_to_1wk_renewal_info.appAccountToken             = None
        e01_upgrade_to_1wk_renewal_info.appTransactionId            = '704897469903383919'
        e01_upgrade_to_1wk_renewal_info.autoRenewProductId          = None
        e01_upgrade_to_1wk_renewal_info.autoRenewStatus             = None
        e01_upgrade_to_1wk_renewal_info.currency                    = 'AUD'
        e01_upgrade_to_1wk_renewal_info.eligibleWinBackOfferIds     = None
        e01_upgrade_to_1wk_renewal_info.environment                 = AppleEnvironment.SANDBOX
        e01_upgrade_to_1wk_renewal_info.expirationIntent            = None
        e01_upgrade_to_1wk_renewal_info.gracePeriodExpiresDate      = None
        e01_upgrade_to_1wk_renewal_info.isInBillingRetryPeriod      = None
        e01_upgrade_to_1wk_renewal_info.offerDiscountType           = None
        e01_upgrade_to_1wk_renewal_info.offerIdentifier             = None
        e01_upgrade_to_1wk_renewal_info.offerPeriod                 = None
        e01_upgrade_to_1wk_renewal_info.offerType                   = None
        e01_upgrade_to_1wk_renewal_info.originalTransactionId       = '2000001024993299'
        e01_upgrade_to_1wk_renewal_info.priceIncreaseStatus         = None
        e01_upgrade_to_1wk_renewal_info.productId                   = 'com.getsession.org.pro_sub'
        e01_upgrade_to_1wk_renewal_info.rawAutoRenewStatus          = None
        e01_upgrade_to_1wk_renewal_info.rawEnvironment              = 'Sandbox'
        e01_upgrade_to_1wk_renewal_info.rawExpirationIntent         = None
        e01_upgrade_to_1wk_renewal_info.rawOfferDiscountType        = None
        e01_upgrade_to_1wk_renewal_info.rawOfferType                = None
        e01_upgrade_to_1wk_renewal_info.rawPriceIncreaseStatus      = None
        e01_upgrade_to_1wk_renewal_info.recentSubscriptionStartDate = None
        e01_upgrade_to_1wk_renewal_info.renewalDate                 = None
        e01_upgrade_to_1wk_renewal_info.renewalPrice                = None
        e01_upgrade_to_1wk_renewal_info.signedDate                  = 1759727799810

        # NOTE: Signed Transaction Info
        e01_upgrade_to_1wk_tx_info                                  = AppleJWSTransactionDecodedPayload()
        e01_upgrade_to_1wk_tx_info.appAccountToken                  = None
        e01_upgrade_to_1wk_tx_info.appTransactionId                 = '704897469903383919'
        e01_upgrade_to_1wk_tx_info.bundleId                         = 'com.loki-project.loki-messenger'
        e01_upgrade_to_1wk_tx_info.currency                         = 'AUD'
        e01_upgrade_to_1wk_tx_info.environment                      = AppleEnvironment.SANDBOX
        e01_upgrade_to_1wk_tx_info.expiresDate                      = 1759727970000
        e01_upgrade_to_1wk_tx_info.inAppOwnershipType               = AppleInAppOwnershipType.PURCHASED
        e01_upgrade_to_1wk_tx_info.isUpgraded                       = None
        e01_upgrade_to_1wk_tx_info.offerDiscountType                = None
        e01_upgrade_to_1wk_tx_info.offerIdentifier                  = None
        e01_upgrade_to_1wk_tx_info.offerPeriod                      = None
        e01_upgrade_to_1wk_tx_info.offerType                        = None
        e01_upgrade_to_1wk_tx_info.originalPurchaseDate             = 1759301833000
        e01_upgrade_to_1wk_tx_info.originalTransactionId            = '2000001024993299'
        e01_upgrade_to_1wk_tx_info.price                            = 1990
        e01_upgrade_to_1wk_tx_info.productId                        = 'com.getsession.org.pro_sub'
        e01_upgrade_to_1wk_tx_info.purchaseDate                     = 1759727790000
        e01_upgrade_to_1wk_tx_info.quantity                         = 1
        e01_upgrade_to_1wk_tx_info.rawEnvironment                   = 'Sandbox'
        e01_upgrade_to_1wk_tx_info.rawInAppOwnershipType            = 'PURCHASED'
        e01_upgrade_to_1wk_tx_info.rawOfferDiscountType             = None
        e01_upgrade_to_1wk_tx_info.rawOfferType                     = None
        e01_upgrade_to_1wk_tx_info.rawRevocationReason              = None
        e01_upgrade_to_1wk_tx_info.rawTransactionReason             = 'PURCHASE'
        e01_upgrade_to_1wk_tx_info.rawType                          = 'Auto-Renewable Subscription'
        e01_upgrade_to_1wk_tx_info.revocationDate                   = None
        e01_upgrade_to_1wk_tx_info.revocationReason                 = None
        e01_upgrade_to_1wk_tx_info.signedDate                       = 1759727799810
        e01_upgrade_to_1wk_tx_info.storefront                       = 'AUS'
        e01_upgrade_to_1wk_tx_info.storefrontId                     = '143460'
        e01_upgrade_to_1wk_tx_info.subscriptionGroupIdentifier      = '21752814'
        e01_upgrade_to_1wk_tx_info.transactionId                    = '2000001027701928'
        e01_upgrade_to_1wk_tx_info.transactionReason                = AppleTransactionReason.PURCHASE
        e01_upgrade_to_1wk_tx_info.type                             = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        e01_upgrade_to_1wk_tx_info.webOrderLineItemId               = '2000000114202140'

        e01_upgrade_to_1wk_decoded_notification                     = platform_apple.DecodedNotification(body=e01_upgrade_to_1wk_body, tx_info=e01_upgrade_to_1wk_tx_info, renewal_info=e01_upgrade_to_1wk_renewal_info)

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        e02_disable_auto_renew_body                                     = AppleResponseBodyV2DecodedPayload()
        e02_disable_auto_renew_body_data                                = AppleData()
        e02_disable_auto_renew_body_data.appAppleId                     = 1470168868
        e02_disable_auto_renew_body_data.bundleId                       = 'com.loki-project.loki-messenger'
        e02_disable_auto_renew_body_data.bundleVersion                  = '637'
        e02_disable_auto_renew_body_data.consumptionRequestReason       = None
        e02_disable_auto_renew_body_data.environment                    = AppleEnvironment.SANDBOX
        e02_disable_auto_renew_body_data.rawConsumptionRequestReason    = None
        e02_disable_auto_renew_body_data.rawEnvironment                 = 'Sandbox'
        e02_disable_auto_renew_body_data.rawStatus                      = 1
        e02_disable_auto_renew_body_data.signedRenewalInfo              = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MCwic2lnbmVkRGF0ZSI6MTc1OTcyNzgyMTk1MiwiZW52aXJvbm1lbnQiOiJTYW5kYm94IiwicmVjZW50U3Vic2NyaXB0aW9uU3RhcnREYXRlIjoxNzU5NzI3Nzc4MDAwLCJyZW5ld2FsRGF0ZSI6MTc1OTcyNzk3MDAwMCwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.fR7KkdRfmctSc8VYJsGLNNnqtoXmHgmvainD-4L0_5iVBDQlkiTGYtuoH4lyiwZY98X8POdqiU-gdhXDfv3pLQ'
        e02_disable_auto_renew_body_data.signedTransactionInfo          = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNzcwMTkyOCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTE0MjAyMTQwIiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTcyNzc5MDAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5NzI3OTcwMDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc4MjE5NTIsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.qxH5ABfXbiUnCQSe9QlwXMLdbhdE1FI1-1IRuKnYpw0Eel1Z4NDrGFasT-TMbAAFa8e4NCOAu_QdKsPtygluOg'
        e02_disable_auto_renew_body_data.status                         = AppleStatus.ACTIVE
        e02_disable_auto_renew_body.data                                = e02_disable_auto_renew_body_data
        e02_disable_auto_renew_body.externalPurchaseToken               = None
        e02_disable_auto_renew_body.notificationType                    = AppleNotificationTypeV2.DID_CHANGE_RENEWAL_STATUS
        e02_disable_auto_renew_body.notificationUUID                    = '6a8251d2-425d-49a3-81b6-517cefc4a5ea'
        e02_disable_auto_renew_body.rawNotificationType                 = 'DID_CHANGE_RENEWAL_STATUS'
        e02_disable_auto_renew_body.rawSubtype                          = 'AUTO_RENEW_DISABLED'
        e02_disable_auto_renew_body.signedDate                          = 1759727821952
        e02_disable_auto_renew_body.subtype                             = AppleSubtype.AUTO_RENEW_DISABLED
        e02_disable_auto_renew_body.summary                             = None
        e02_disable_auto_renew_body.version                             = '2.0'

        # NOTE: Signed Renewal Info
        e02_disable_auto_renew_renewal_info                             = AppleJWSRenewalInfoDecodedPayload()
        e02_disable_auto_renew_renewal_info.appAccountToken             = None
        e02_disable_auto_renew_renewal_info.appTransactionId            = '704897469903383919'
        e02_disable_auto_renew_renewal_info.autoRenewProductId          = None
        e02_disable_auto_renew_renewal_info.autoRenewStatus             = None
        e02_disable_auto_renew_renewal_info.currency                    = 'AUD'
        e02_disable_auto_renew_renewal_info.eligibleWinBackOfferIds     = None
        e02_disable_auto_renew_renewal_info.environment                 = AppleEnvironment.SANDBOX
        e02_disable_auto_renew_renewal_info.expirationIntent            = None
        e02_disable_auto_renew_renewal_info.gracePeriodExpiresDate      = None
        e02_disable_auto_renew_renewal_info.isInBillingRetryPeriod      = None
        e02_disable_auto_renew_renewal_info.offerDiscountType           = None
        e02_disable_auto_renew_renewal_info.offerIdentifier             = None
        e02_disable_auto_renew_renewal_info.offerPeriod                 = None
        e02_disable_auto_renew_renewal_info.offerType                   = None
        e02_disable_auto_renew_renewal_info.originalTransactionId       = '2000001024993299'
        e02_disable_auto_renew_renewal_info.priceIncreaseStatus         = None
        e02_disable_auto_renew_renewal_info.productId                   = 'com.getsession.org.pro_sub'
        e02_disable_auto_renew_renewal_info.rawAutoRenewStatus          = None
        e02_disable_auto_renew_renewal_info.rawEnvironment              = 'Sandbox'
        e02_disable_auto_renew_renewal_info.rawExpirationIntent         = None
        e02_disable_auto_renew_renewal_info.rawOfferDiscountType        = None
        e02_disable_auto_renew_renewal_info.rawOfferType                = None
        e02_disable_auto_renew_renewal_info.rawPriceIncreaseStatus      = None
        e02_disable_auto_renew_renewal_info.recentSubscriptionStartDate = None
        e02_disable_auto_renew_renewal_info.renewalDate                 = None
        e02_disable_auto_renew_renewal_info.renewalPrice                = None
        e02_disable_auto_renew_renewal_info.signedDate                  = 1759727821952

        # NOTE: Signed Transaction Info
        e02_disable_auto_renew_tx_info                                  = AppleJWSTransactionDecodedPayload()
        e02_disable_auto_renew_tx_info.appAccountToken                  = None
        e02_disable_auto_renew_tx_info.appTransactionId                 = '704897469903383919'
        e02_disable_auto_renew_tx_info.bundleId                         = 'com.loki-project.loki-messenger'
        e02_disable_auto_renew_tx_info.currency                         = 'AUD'
        e02_disable_auto_renew_tx_info.environment                      = AppleEnvironment.SANDBOX
        e02_disable_auto_renew_tx_info.expiresDate                      = 1759727970000
        e02_disable_auto_renew_tx_info.inAppOwnershipType               = AppleInAppOwnershipType.PURCHASED
        e02_disable_auto_renew_tx_info.isUpgraded                       = None
        e02_disable_auto_renew_tx_info.offerDiscountType                = None
        e02_disable_auto_renew_tx_info.offerIdentifier                  = None
        e02_disable_auto_renew_tx_info.offerPeriod                      = None
        e02_disable_auto_renew_tx_info.offerType                        = None
        e02_disable_auto_renew_tx_info.originalPurchaseDate             = 1759301833000
        e02_disable_auto_renew_tx_info.originalTransactionId            = '2000001024993299'
        e02_disable_auto_renew_tx_info.price                            = 1990
        e02_disable_auto_renew_tx_info.productId                        = 'com.getsession.org.pro_sub'
        e02_disable_auto_renew_tx_info.purchaseDate                     = 1759727790000
        e02_disable_auto_renew_tx_info.quantity                         = 1
        e02_disable_auto_renew_tx_info.rawEnvironment                   = 'Sandbox'
        e02_disable_auto_renew_tx_info.rawInAppOwnershipType            = 'PURCHASED'
        e02_disable_auto_renew_tx_info.rawOfferDiscountType             = None
        e02_disable_auto_renew_tx_info.rawOfferType                     = None
        e02_disable_auto_renew_tx_info.rawRevocationReason              = None
        e02_disable_auto_renew_tx_info.rawTransactionReason             = 'PURCHASE'
        e02_disable_auto_renew_tx_info.rawType                          = 'Auto-Renewable Subscription'
        e02_disable_auto_renew_tx_info.revocationDate                   = None
        e02_disable_auto_renew_tx_info.revocationReason                 = None
        e02_disable_auto_renew_tx_info.signedDate                       = 1759727821952
        e02_disable_auto_renew_tx_info.storefront                       = 'AUS'
        e02_disable_auto_renew_tx_info.storefrontId                     = '143460'
        e02_disable_auto_renew_tx_info.subscriptionGroupIdentifier      = '21752814'
        e02_disable_auto_renew_tx_info.transactionId                    = '2000001027701928'
        e02_disable_auto_renew_tx_info.transactionReason                = AppleTransactionReason.PURCHASE
        e02_disable_auto_renew_tx_info.type                             = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        e02_disable_auto_renew_tx_info.webOrderLineItemId               = '2000000114202140'

        e02_disable_auto_renew_decoded_notification                     = platform_apple.DecodedNotification(body=e02_disable_auto_renew_body, tx_info=e02_disable_auto_renew_tx_info, renewal_info=e02_disable_auto_renew_renewal_info)

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        e03_queue_downgrade_to_3_months_body                                       = AppleResponseBodyV2DecodedPayload()
        e03_queue_downgrade_to_3_months_body_data                                  = AppleData()
        e03_queue_downgrade_to_3_months_body_data.appAppleId                       = 1470168868
        e03_queue_downgrade_to_3_months_body_data.bundleId                         = 'com.loki-project.loki-messenger'
        e03_queue_downgrade_to_3_months_body_data.bundleVersion                    = '637'
        e03_queue_downgrade_to_3_months_body_data.consumptionRequestReason         = None
        e03_queue_downgrade_to_3_months_body_data.environment                      = AppleEnvironment.SANDBOX
        e03_queue_downgrade_to_3_months_body_data.rawConsumptionRequestReason      = None
        e03_queue_downgrade_to_3_months_body_data.rawEnvironment                   = 'Sandbox'
        e03_queue_downgrade_to_3_months_body_data.rawStatus                        = 1
        e03_queue_downgrade_to_3_months_body_data.signedRenewalInfo                = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWJfM19tb250aHMiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MSwicmVuZXdhbFByaWNlIjo1OTkwLCJjdXJyZW5jeSI6IkFVRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc4Mzg0NTAsImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc1OTcyNzc3ODAwMCwicmVuZXdhbERhdGUiOjE3NTk3Mjc5NzAwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.x9ex7aFlmHJ3U286ZLPluVX5ES0PjgVzIVOxxzKVjrNjRi-GVsSHuDSJbz_wkF0zBBtvEcOOgOnjIqiHVRPmMA'
        e03_queue_downgrade_to_3_months_body_data.signedTransactionInfo            = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNzcwMTkyOCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTE0MjAyMTQwIiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTcyNzc5MDAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5NzI3OTcwMDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc4Mzg0NTAsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.CjL3XeQfKQaz-bCwrYsDGlVKTHgoeg1zXXsheGtsuMsqzxJrjF7VdutsywY_YyQ7lzWiOuEB4nqXX96ZvJpJiA'
        e03_queue_downgrade_to_3_months_body_data.status                           = AppleStatus.ACTIVE
        e03_queue_downgrade_to_3_months_body.data                                  = e03_queue_downgrade_to_3_months_body_data
        e03_queue_downgrade_to_3_months_body.externalPurchaseToken                 = None
        e03_queue_downgrade_to_3_months_body.notificationType                      = AppleNotificationTypeV2.DID_CHANGE_RENEWAL_PREF
        e03_queue_downgrade_to_3_months_body.notificationUUID                      = '01c574dc-64b7-45d3-889a-5fdcb08fb5c0'
        e03_queue_downgrade_to_3_months_body.rawNotificationType                   = 'DID_CHANGE_RENEWAL_PREF'
        e03_queue_downgrade_to_3_months_body.rawSubtype                            = 'DOWNGRADE'
        e03_queue_downgrade_to_3_months_body.signedDate                            = 1759727838450
        e03_queue_downgrade_to_3_months_body.subtype                               = AppleSubtype.DOWNGRADE
        e03_queue_downgrade_to_3_months_body.summary                               = None
        e03_queue_downgrade_to_3_months_body.version                               = '2.0'

        # NOTE: Signed Renewal Info
        e03_queue_downgrade_to_3_months_renewal_info                               = AppleJWSRenewalInfoDecodedPayload()
        e03_queue_downgrade_to_3_months_renewal_info.appAccountToken               = None
        e03_queue_downgrade_to_3_months_renewal_info.appTransactionId              = '704897469903383919'
        e03_queue_downgrade_to_3_months_renewal_info.autoRenewProductId            = None
        e03_queue_downgrade_to_3_months_renewal_info.autoRenewStatus               = None
        e03_queue_downgrade_to_3_months_renewal_info.currency                      = 'AUD'
        e03_queue_downgrade_to_3_months_renewal_info.eligibleWinBackOfferIds       = None
        e03_queue_downgrade_to_3_months_renewal_info.environment                   = AppleEnvironment.SANDBOX
        e03_queue_downgrade_to_3_months_renewal_info.expirationIntent              = None
        e03_queue_downgrade_to_3_months_renewal_info.gracePeriodExpiresDate        = None
        e03_queue_downgrade_to_3_months_renewal_info.isInBillingRetryPeriod        = None
        e03_queue_downgrade_to_3_months_renewal_info.offerDiscountType             = None
        e03_queue_downgrade_to_3_months_renewal_info.offerIdentifier               = None
        e03_queue_downgrade_to_3_months_renewal_info.offerPeriod                   = None
        e03_queue_downgrade_to_3_months_renewal_info.offerType                     = None
        e03_queue_downgrade_to_3_months_renewal_info.originalTransactionId         = '2000001024993299'
        e03_queue_downgrade_to_3_months_renewal_info.priceIncreaseStatus           = None
        e03_queue_downgrade_to_3_months_renewal_info.productId                     = 'com.getsession.org.pro_sub'
        e03_queue_downgrade_to_3_months_renewal_info.rawAutoRenewStatus            = None
        e03_queue_downgrade_to_3_months_renewal_info.rawEnvironment                = 'Sandbox'
        e03_queue_downgrade_to_3_months_renewal_info.rawExpirationIntent           = None
        e03_queue_downgrade_to_3_months_renewal_info.rawOfferDiscountType          = None
        e03_queue_downgrade_to_3_months_renewal_info.rawOfferType                  = None
        e03_queue_downgrade_to_3_months_renewal_info.rawPriceIncreaseStatus        = None
        e03_queue_downgrade_to_3_months_renewal_info.recentSubscriptionStartDate   = None
        e03_queue_downgrade_to_3_months_renewal_info.renewalDate                   = None
        e03_queue_downgrade_to_3_months_renewal_info.renewalPrice                  = None
        e03_queue_downgrade_to_3_months_renewal_info.signedDate                    = 1759727838450

        # NOTE: Signed Transaction Info
        e03_queue_downgrade_to_3_months_tx_info                                    = AppleJWSTransactionDecodedPayload()
        e03_queue_downgrade_to_3_months_tx_info.appAccountToken                    = None
        e03_queue_downgrade_to_3_months_tx_info.appTransactionId                   = '704897469903383919'
        e03_queue_downgrade_to_3_months_tx_info.bundleId                           = 'com.loki-project.loki-messenger'
        e03_queue_downgrade_to_3_months_tx_info.currency                           = 'AUD'
        e03_queue_downgrade_to_3_months_tx_info.environment                        = AppleEnvironment.SANDBOX
        e03_queue_downgrade_to_3_months_tx_info.expiresDate                        = 1759727970000
        e03_queue_downgrade_to_3_months_tx_info.inAppOwnershipType                 = AppleInAppOwnershipType.PURCHASED
        e03_queue_downgrade_to_3_months_tx_info.isUpgraded                         = None
        e03_queue_downgrade_to_3_months_tx_info.offerDiscountType                  = None
        e03_queue_downgrade_to_3_months_tx_info.offerIdentifier                    = None
        e03_queue_downgrade_to_3_months_tx_info.offerPeriod                        = None
        e03_queue_downgrade_to_3_months_tx_info.offerType                          = None
        e03_queue_downgrade_to_3_months_tx_info.originalPurchaseDate               = 1759301833000
        e03_queue_downgrade_to_3_months_tx_info.originalTransactionId              = '2000001024993299'
        e03_queue_downgrade_to_3_months_tx_info.price                              = 1990
        e03_queue_downgrade_to_3_months_tx_info.productId                          = 'com.getsession.org.pro_sub'
        e03_queue_downgrade_to_3_months_tx_info.purchaseDate                       = 1759727790000
        e03_queue_downgrade_to_3_months_tx_info.quantity                           = 1
        e03_queue_downgrade_to_3_months_tx_info.rawEnvironment                     = 'Sandbox'
        e03_queue_downgrade_to_3_months_tx_info.rawInAppOwnershipType              = 'PURCHASED'
        e03_queue_downgrade_to_3_months_tx_info.rawOfferDiscountType               = None
        e03_queue_downgrade_to_3_months_tx_info.rawOfferType                       = None
        e03_queue_downgrade_to_3_months_tx_info.rawRevocationReason                = None
        e03_queue_downgrade_to_3_months_tx_info.rawTransactionReason               = 'PURCHASE'
        e03_queue_downgrade_to_3_months_tx_info.rawType                            = 'Auto-Renewable Subscription'
        e03_queue_downgrade_to_3_months_tx_info.revocationDate                     = None
        e03_queue_downgrade_to_3_months_tx_info.revocationReason                   = None
        e03_queue_downgrade_to_3_months_tx_info.signedDate                         = 1759727838450
        e03_queue_downgrade_to_3_months_tx_info.storefront                         = 'AUS'
        e03_queue_downgrade_to_3_months_tx_info.storefrontId                       = '143460'
        e03_queue_downgrade_to_3_months_tx_info.subscriptionGroupIdentifier        = '21752814'
        e03_queue_downgrade_to_3_months_tx_info.transactionId                      = '2000001027701928'
        e03_queue_downgrade_to_3_months_tx_info.transactionReason                  = AppleTransactionReason.PURCHASE
        e03_queue_downgrade_to_3_months_tx_info.type                               = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        e03_queue_downgrade_to_3_months_tx_info.webOrderLineItemId                 = '2000000114202140'

        e03_queue_downgrade_to_3_months_decoded_notification                       = platform_apple.DecodedNotification(body=e03_queue_downgrade_to_3_months_body, tx_info=e03_queue_downgrade_to_3_months_tx_info, renewal_info=e03_queue_downgrade_to_3_months_renewal_info)

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        e04_cancel_downgrade_to_3_months_body                                      = AppleResponseBodyV2DecodedPayload()
        e04_cancel_downgrade_to_3_months_body_data                                 = AppleData()
        e04_cancel_downgrade_to_3_months_body_data.appAppleId                      = 1470168868
        e04_cancel_downgrade_to_3_months_body_data.bundleId                        = 'com.loki-project.loki-messenger'
        e04_cancel_downgrade_to_3_months_body_data.bundleVersion                   = '637'
        e04_cancel_downgrade_to_3_months_body_data.consumptionRequestReason        = None
        e04_cancel_downgrade_to_3_months_body_data.environment                     = AppleEnvironment.SANDBOX
        e04_cancel_downgrade_to_3_months_body_data.rawConsumptionRequestReason     = None
        e04_cancel_downgrade_to_3_months_body_data.rawEnvironment                  = 'Sandbox'
        e04_cancel_downgrade_to_3_months_body_data.rawStatus                       = 1
        e04_cancel_downgrade_to_3_months_body_data.signedRenewalInfo               = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MSwicmVuZXdhbFByaWNlIjoxOTkwLCJjdXJyZW5jeSI6IkFVRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc4NjYyMzEsImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc1OTcyNzc3ODAwMCwicmVuZXdhbERhdGUiOjE3NTk3Mjc5NzAwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.TISJVF_0VsKDc7UAwT3Z4vM8oSRco0cPGQ4z6r3kAi44Ya1f1Rlppfcy49QrnhZGqubPusYnBVG8fMUCXiX3jw'
        e04_cancel_downgrade_to_3_months_body_data.signedTransactionInfo           = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNzcwMTkyOCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTE0MjAyMTQwIiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTcyNzc5MDAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5NzI3OTcwMDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc4NjYyMzEsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.tJMEYs32Qyqgnhx3ITrzpgERSIRi_1KjfF5H9Eyhg1ZRb-yhgoVw0KfbE5cfQD_JIxf-BVYLXmzsG6tzjeE0cg'
        e04_cancel_downgrade_to_3_months_body_data.status                          = AppleStatus.ACTIVE
        e04_cancel_downgrade_to_3_months_body.data                                 = e04_cancel_downgrade_to_3_months_body_data
        e04_cancel_downgrade_to_3_months_body.externalPurchaseToken                = None
        e04_cancel_downgrade_to_3_months_body.notificationType                     = AppleNotificationTypeV2.DID_CHANGE_RENEWAL_PREF
        e04_cancel_downgrade_to_3_months_body.notificationUUID                     = 'a7a530f8-2e03-4b16-ba4c-cee50725f8d8'
        e04_cancel_downgrade_to_3_months_body.rawNotificationType                  = 'DID_CHANGE_RENEWAL_PREF'
        e04_cancel_downgrade_to_3_months_body.rawSubtype                           = None
        e04_cancel_downgrade_to_3_months_body.signedDate                           = 1759727866231
        e04_cancel_downgrade_to_3_months_body.subtype                              = None
        e04_cancel_downgrade_to_3_months_body.summary                              = None
        e04_cancel_downgrade_to_3_months_body.version                              = '2.0'

        # NOTE: Signed Renewal Info
        e04_cancel_downgrade_to_3_months_renewal_info                              = AppleJWSRenewalInfoDecodedPayload()
        e04_cancel_downgrade_to_3_months_renewal_info.appAccountToken              = None
        e04_cancel_downgrade_to_3_months_renewal_info.appTransactionId             = '704897469903383919'
        e04_cancel_downgrade_to_3_months_renewal_info.autoRenewProductId           = None
        e04_cancel_downgrade_to_3_months_renewal_info.autoRenewStatus              = None
        e04_cancel_downgrade_to_3_months_renewal_info.currency                     = 'AUD'
        e04_cancel_downgrade_to_3_months_renewal_info.eligibleWinBackOfferIds      = None
        e04_cancel_downgrade_to_3_months_renewal_info.environment                  = AppleEnvironment.SANDBOX
        e04_cancel_downgrade_to_3_months_renewal_info.expirationIntent             = None
        e04_cancel_downgrade_to_3_months_renewal_info.gracePeriodExpiresDate       = None
        e04_cancel_downgrade_to_3_months_renewal_info.isInBillingRetryPeriod       = None
        e04_cancel_downgrade_to_3_months_renewal_info.offerDiscountType            = None
        e04_cancel_downgrade_to_3_months_renewal_info.offerIdentifier              = None
        e04_cancel_downgrade_to_3_months_renewal_info.offerPeriod                  = None
        e04_cancel_downgrade_to_3_months_renewal_info.offerType                    = None
        e04_cancel_downgrade_to_3_months_renewal_info.originalTransactionId        = '2000001024993299'
        e04_cancel_downgrade_to_3_months_renewal_info.priceIncreaseStatus          = None
        e04_cancel_downgrade_to_3_months_renewal_info.productId                    = 'com.getsession.org.pro_sub'
        e04_cancel_downgrade_to_3_months_renewal_info.rawAutoRenewStatus           = None
        e04_cancel_downgrade_to_3_months_renewal_info.rawEnvironment               = 'Sandbox'
        e04_cancel_downgrade_to_3_months_renewal_info.rawExpirationIntent          = None
        e04_cancel_downgrade_to_3_months_renewal_info.rawOfferDiscountType         = None
        e04_cancel_downgrade_to_3_months_renewal_info.rawOfferType                 = None
        e04_cancel_downgrade_to_3_months_renewal_info.rawPriceIncreaseStatus       = None
        e04_cancel_downgrade_to_3_months_renewal_info.recentSubscriptionStartDate  = None
        e04_cancel_downgrade_to_3_months_renewal_info.renewalDate                  = None
        e04_cancel_downgrade_to_3_months_renewal_info.renewalPrice                 = None
        e04_cancel_downgrade_to_3_months_renewal_info.signedDate                   = 1759727866231

        # NOTE: Signed Transaction Info
        e04_cancel_downgrade_to_3_months_tx_info                                   = AppleJWSTransactionDecodedPayload()
        e04_cancel_downgrade_to_3_months_tx_info.appAccountToken                   = None
        e04_cancel_downgrade_to_3_months_tx_info.appTransactionId                  = '704897469903383919'
        e04_cancel_downgrade_to_3_months_tx_info.bundleId                          = 'com.loki-project.loki-messenger'
        e04_cancel_downgrade_to_3_months_tx_info.currency                          = 'AUD'
        e04_cancel_downgrade_to_3_months_tx_info.environment                       = AppleEnvironment.SANDBOX
        e04_cancel_downgrade_to_3_months_tx_info.expiresDate                       = 1759727970000
        e04_cancel_downgrade_to_3_months_tx_info.inAppOwnershipType                = AppleInAppOwnershipType.PURCHASED
        e04_cancel_downgrade_to_3_months_tx_info.isUpgraded                        = None
        e04_cancel_downgrade_to_3_months_tx_info.offerDiscountType                 = None
        e04_cancel_downgrade_to_3_months_tx_info.offerIdentifier                   = None
        e04_cancel_downgrade_to_3_months_tx_info.offerPeriod                       = None
        e04_cancel_downgrade_to_3_months_tx_info.offerType                         = None
        e04_cancel_downgrade_to_3_months_tx_info.originalPurchaseDate              = 1759301833000
        e04_cancel_downgrade_to_3_months_tx_info.originalTransactionId             = '2000001024993299'
        e04_cancel_downgrade_to_3_months_tx_info.price                             = 1990
        e04_cancel_downgrade_to_3_months_tx_info.productId                         = 'com.getsession.org.pro_sub'
        e04_cancel_downgrade_to_3_months_tx_info.purchaseDate                      = 1759727790000
        e04_cancel_downgrade_to_3_months_tx_info.quantity                          = 1
        e04_cancel_downgrade_to_3_months_tx_info.rawEnvironment                    = 'Sandbox'
        e04_cancel_downgrade_to_3_months_tx_info.rawInAppOwnershipType             = 'PURCHASED'
        e04_cancel_downgrade_to_3_months_tx_info.rawOfferDiscountType              = None
        e04_cancel_downgrade_to_3_months_tx_info.rawOfferType                      = None
        e04_cancel_downgrade_to_3_months_tx_info.rawRevocationReason               = None
        e04_cancel_downgrade_to_3_months_tx_info.rawTransactionReason              = 'PURCHASE'
        e04_cancel_downgrade_to_3_months_tx_info.rawType                           = 'Auto-Renewable Subscription'
        e04_cancel_downgrade_to_3_months_tx_info.revocationDate                    = None
        e04_cancel_downgrade_to_3_months_tx_info.revocationReason                  = None
        e04_cancel_downgrade_to_3_months_tx_info.signedDate                        = 1759727866231
        e04_cancel_downgrade_to_3_months_tx_info.storefront                        = 'AUS'
        e04_cancel_downgrade_to_3_months_tx_info.storefrontId                      = '143460'
        e04_cancel_downgrade_to_3_months_tx_info.subscriptionGroupIdentifier       = '21752814'
        e04_cancel_downgrade_to_3_months_tx_info.transactionId                     = '2000001027701928'
        e04_cancel_downgrade_to_3_months_tx_info.transactionReason                 = AppleTransactionReason.PURCHASE
        e04_cancel_downgrade_to_3_months_tx_info.type                              = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        e04_cancel_downgrade_to_3_months_tx_info.webOrderLineItemId                = '2000000114202140'

        e04_cancel_downgrade_to_3_months_decoded_notification                      = platform_apple.DecodedNotification(body=e04_cancel_downgrade_to_3_months_body, tx_info=e04_cancel_downgrade_to_3_months_tx_info, renewal_info=e04_cancel_downgrade_to_3_months_renewal_info)

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        e05_disable_auto_renew_body                                     = AppleResponseBodyV2DecodedPayload()
        e05_disable_auto_renew_body_data                                = AppleData()
        e05_disable_auto_renew_body_data.appAppleId                     = 1470168868
        e05_disable_auto_renew_body_data.bundleId                       = 'com.loki-project.loki-messenger'
        e05_disable_auto_renew_body_data.bundleVersion                  = '637'
        e05_disable_auto_renew_body_data.consumptionRequestReason       = None
        e05_disable_auto_renew_body_data.environment                    = AppleEnvironment.SANDBOX
        e05_disable_auto_renew_body_data.rawConsumptionRequestReason    = None
        e05_disable_auto_renew_body_data.rawEnvironment                 = 'Sandbox'
        e05_disable_auto_renew_body_data.rawStatus                      = 1
        e05_disable_auto_renew_body_data.signedRenewalInfo              = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MCwic2lnbmVkRGF0ZSI6MTc1OTcyNzg3Njg3NywiZW52aXJvbm1lbnQiOiJTYW5kYm94IiwicmVjZW50U3Vic2NyaXB0aW9uU3RhcnREYXRlIjoxNzU5NzI3Nzc4MDAwLCJyZW5ld2FsRGF0ZSI6MTc1OTcyNzk3MDAwMCwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.5iJPdUIWMXMTQkwipeRQVDhu0d-ykTuNzuhxKuPdSjeOHbnNyi4kZP95RYWmkKyJ37Dt9NFkIBZeMoOVsjHhqw'
        e05_disable_auto_renew_body_data.signedTransactionInfo          = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNzcwMTkyOCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTE0MjAyMTQwIiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTcyNzc5MDAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5NzI3OTcwMDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc4NzY4NzcsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.me1YuoHaLhLPQgwG0oFW672qlEBGCgQVIL9bYvz6FCsHT4R4faGKpcH8U4ScP008mc6AH3jutl2rWWKenG_MoA'
        e05_disable_auto_renew_body_data.status                         = AppleStatus.ACTIVE
        e05_disable_auto_renew_body.data                                = e05_disable_auto_renew_body_data
        e05_disable_auto_renew_body.externalPurchaseToken               = None
        e05_disable_auto_renew_body.notificationType                    = AppleNotificationTypeV2.DID_CHANGE_RENEWAL_STATUS
        e05_disable_auto_renew_body.notificationUUID                    = '2b7ed399-8a88-4445-8a59-3d2017637c15'
        e05_disable_auto_renew_body.rawNotificationType                 = 'DID_CHANGE_RENEWAL_STATUS'
        e05_disable_auto_renew_body.rawSubtype                          = 'AUTO_RENEW_DISABLED'
        e05_disable_auto_renew_body.signedDate                          = 1759727876877
        e05_disable_auto_renew_body.subtype                             = AppleSubtype.AUTO_RENEW_DISABLED
        e05_disable_auto_renew_body.summary                             = None
        e05_disable_auto_renew_body.version                             = '2.0'

        # NOTE: Signed Renewal Info
        e05_disable_auto_renew_renewal_info                             = AppleJWSRenewalInfoDecodedPayload()
        e05_disable_auto_renew_renewal_info.appAccountToken             = None
        e05_disable_auto_renew_renewal_info.appTransactionId            = '704897469903383919'
        e05_disable_auto_renew_renewal_info.autoRenewProductId          = None
        e05_disable_auto_renew_renewal_info.autoRenewStatus             = None
        e05_disable_auto_renew_renewal_info.currency                    = 'AUD'
        e05_disable_auto_renew_renewal_info.eligibleWinBackOfferIds     = None
        e05_disable_auto_renew_renewal_info.environment                 = AppleEnvironment.SANDBOX
        e05_disable_auto_renew_renewal_info.expirationIntent            = None
        e05_disable_auto_renew_renewal_info.gracePeriodExpiresDate      = None
        e05_disable_auto_renew_renewal_info.isInBillingRetryPeriod      = None
        e05_disable_auto_renew_renewal_info.offerDiscountType           = None
        e05_disable_auto_renew_renewal_info.offerIdentifier             = None
        e05_disable_auto_renew_renewal_info.offerPeriod                 = None
        e05_disable_auto_renew_renewal_info.offerType                   = None
        e05_disable_auto_renew_renewal_info.originalTransactionId       = '2000001024993299'
        e05_disable_auto_renew_renewal_info.priceIncreaseStatus         = None
        e05_disable_auto_renew_renewal_info.productId                   = 'com.getsession.org.pro_sub'
        e05_disable_auto_renew_renewal_info.rawAutoRenewStatus          = None
        e05_disable_auto_renew_renewal_info.rawEnvironment              = 'Sandbox'
        e05_disable_auto_renew_renewal_info.rawExpirationIntent         = None
        e05_disable_auto_renew_renewal_info.rawOfferDiscountType        = None
        e05_disable_auto_renew_renewal_info.rawOfferType                = None
        e05_disable_auto_renew_renewal_info.rawPriceIncreaseStatus      = None
        e05_disable_auto_renew_renewal_info.recentSubscriptionStartDate = None
        e05_disable_auto_renew_renewal_info.renewalDate                 = None
        e05_disable_auto_renew_renewal_info.renewalPrice                = None
        e05_disable_auto_renew_renewal_info.signedDate                  = 1759727876877

        # NOTE: Signed Transaction Info
        e05_disable_auto_renew_tx_info                                  = AppleJWSTransactionDecodedPayload()
        e05_disable_auto_renew_tx_info.appAccountToken                  = None
        e05_disable_auto_renew_tx_info.appTransactionId                 = '704897469903383919'
        e05_disable_auto_renew_tx_info.bundleId                         = 'com.loki-project.loki-messenger'
        e05_disable_auto_renew_tx_info.currency                         = 'AUD'
        e05_disable_auto_renew_tx_info.environment                      = AppleEnvironment.SANDBOX
        e05_disable_auto_renew_tx_info.expiresDate                      = 1759727970000
        e05_disable_auto_renew_tx_info.inAppOwnershipType               = AppleInAppOwnershipType.PURCHASED
        e05_disable_auto_renew_tx_info.isUpgraded                       = None
        e05_disable_auto_renew_tx_info.offerDiscountType                = None
        e05_disable_auto_renew_tx_info.offerIdentifier                  = None
        e05_disable_auto_renew_tx_info.offerPeriod                      = None
        e05_disable_auto_renew_tx_info.offerType                        = None
        e05_disable_auto_renew_tx_info.originalPurchaseDate             = 1759301833000
        e05_disable_auto_renew_tx_info.originalTransactionId            = '2000001024993299'
        e05_disable_auto_renew_tx_info.price                            = 1990
        e05_disable_auto_renew_tx_info.productId                        = 'com.getsession.org.pro_sub'
        e05_disable_auto_renew_tx_info.purchaseDate                     = 1759727790000
        e05_disable_auto_renew_tx_info.quantity                         = 1
        e05_disable_auto_renew_tx_info.rawEnvironment                   = 'Sandbox'
        e05_disable_auto_renew_tx_info.rawInAppOwnershipType            = 'PURCHASED'
        e05_disable_auto_renew_tx_info.rawOfferDiscountType             = None
        e05_disable_auto_renew_tx_info.rawOfferType                     = None
        e05_disable_auto_renew_tx_info.rawRevocationReason              = None
        e05_disable_auto_renew_tx_info.rawTransactionReason             = 'PURCHASE'
        e05_disable_auto_renew_tx_info.rawType                          = 'Auto-Renewable Subscription'
        e05_disable_auto_renew_tx_info.revocationDate                   = None
        e05_disable_auto_renew_tx_info.revocationReason                 = None
        e05_disable_auto_renew_tx_info.signedDate                       = 1759727876877
        e05_disable_auto_renew_tx_info.storefront                       = 'AUS'
        e05_disable_auto_renew_tx_info.storefrontId                     = '143460'
        e05_disable_auto_renew_tx_info.subscriptionGroupIdentifier      = '21752814'
        e05_disable_auto_renew_tx_info.transactionId                    = '2000001027701928'
        e05_disable_auto_renew_tx_info.transactionReason                = AppleTransactionReason.PURCHASE
        e05_disable_auto_renew_tx_info.type                             = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        e05_disable_auto_renew_tx_info.webOrderLineItemId               = '2000000114202140'

        e05_disable_auto_renew_decoded_notification                     = platform_apple.DecodedNotification(body=e05_disable_auto_renew_body, tx_info=e05_disable_auto_renew_tx_info, renewal_info=e05_disable_auto_renew_renewal_info)

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        e06_expire_voluntary_body                                       = AppleResponseBodyV2DecodedPayload()
        e06_expire_voluntary_body_data                                  = AppleData()
        e06_expire_voluntary_body_data.appAppleId                       = 1470168868
        e06_expire_voluntary_body_data.bundleId                         = 'com.loki-project.loki-messenger'
        e06_expire_voluntary_body_data.bundleVersion                    = '637'
        e06_expire_voluntary_body_data.consumptionRequestReason         = None
        e06_expire_voluntary_body_data.environment                      = AppleEnvironment.SANDBOX
        e06_expire_voluntary_body_data.rawConsumptionRequestReason      = None
        e06_expire_voluntary_body_data.rawEnvironment                   = 'Sandbox'
        e06_expire_voluntary_body_data.rawStatus                        = 2
        e06_expire_voluntary_body_data.signedRenewalInfo                = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJleHBpcmF0aW9uSW50ZW50IjoxLCJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MCwiaXNJbkJpbGxpbmdSZXRyeVBlcmlvZCI6ZmFsc2UsInNpZ25lZERhdGUiOjE3NTk3Mjc5ODU3OTksImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc1OTcyNzc3ODAwMCwicmVuZXdhbERhdGUiOjE3NTk3Mjc5NzAwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.VYSGUnH9JX-BUvKERAICKF_BTIAyBmZwXaLsjh1jFRnfuaulaP9Fk_jW4TUubVfwNx54I6lCFndQkb0LerPXig'
        e06_expire_voluntary_body_data.signedTransactionInfo            = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNzcwMTkyOCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTE0MjAyMTQwIiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTcyNzc5MDAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5NzI3OTcwMDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc5ODU3OTksImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.ySyuX_8zEZNC7Csjeb-iNYEI4xrpOkX_uIiIBbLfKaAtRMkUd_8HhNgK_6mqhC-YRyis0AGr3JqUqDchBpitFg'
        e06_expire_voluntary_body_data.status                           = AppleStatus.EXPIRED
        e06_expire_voluntary_body.data                                  = e06_expire_voluntary_body_data
        e06_expire_voluntary_body.externalPurchaseToken                 = None
        e06_expire_voluntary_body.notificationType                      = AppleNotificationTypeV2.EXPIRED
        e06_expire_voluntary_body.notificationUUID                      = 'ae5e6496-626b-4c23-828f-3fa9143c2f5e'
        e06_expire_voluntary_body.rawNotificationType                   = 'EXPIRED'
        e06_expire_voluntary_body.rawSubtype                            = 'VOLUNTARY'
        e06_expire_voluntary_body.signedDate                            = 1759727985799
        e06_expire_voluntary_body.subtype                               = AppleSubtype.VOLUNTARY
        e06_expire_voluntary_body.summary                               = None
        e06_expire_voluntary_body.version                               = '2.0'

        # NOTE: Signed Renewal Info
        e06_expire_voluntary_renewal_info                               = AppleJWSRenewalInfoDecodedPayload()
        e06_expire_voluntary_renewal_info.appAccountToken               = None
        e06_expire_voluntary_renewal_info.appTransactionId              = '704897469903383919'
        e06_expire_voluntary_renewal_info.autoRenewProductId            = None
        e06_expire_voluntary_renewal_info.autoRenewStatus               = None
        e06_expire_voluntary_renewal_info.currency                      = 'AUD'
        e06_expire_voluntary_renewal_info.eligibleWinBackOfferIds       = None
        e06_expire_voluntary_renewal_info.environment                   = AppleEnvironment.SANDBOX
        e06_expire_voluntary_renewal_info.expirationIntent              = None
        e06_expire_voluntary_renewal_info.gracePeriodExpiresDate        = None
        e06_expire_voluntary_renewal_info.isInBillingRetryPeriod        = None
        e06_expire_voluntary_renewal_info.offerDiscountType             = None
        e06_expire_voluntary_renewal_info.offerIdentifier               = None
        e06_expire_voluntary_renewal_info.offerPeriod                   = None
        e06_expire_voluntary_renewal_info.offerType                     = None
        e06_expire_voluntary_renewal_info.originalTransactionId         = '2000001024993299'
        e06_expire_voluntary_renewal_info.priceIncreaseStatus           = None
        e06_expire_voluntary_renewal_info.productId                     = 'com.getsession.org.pro_sub'
        e06_expire_voluntary_renewal_info.rawAutoRenewStatus            = None
        e06_expire_voluntary_renewal_info.rawEnvironment                = 'Sandbox'
        e06_expire_voluntary_renewal_info.rawExpirationIntent           = None
        e06_expire_voluntary_renewal_info.rawOfferDiscountType          = None
        e06_expire_voluntary_renewal_info.rawOfferType                  = None
        e06_expire_voluntary_renewal_info.rawPriceIncreaseStatus        = None
        e06_expire_voluntary_renewal_info.recentSubscriptionStartDate   = None
        e06_expire_voluntary_renewal_info.renewalDate                   = None
        e06_expire_voluntary_renewal_info.renewalPrice                  = None
        e06_expire_voluntary_renewal_info.signedDate                    = 1759727985799

        # NOTE: Signed Transaction Info
        e06_expire_voluntary_tx_info                                    = AppleJWSTransactionDecodedPayload()
        e06_expire_voluntary_tx_info.appAccountToken                    = None
        e06_expire_voluntary_tx_info.appTransactionId                   = '704897469903383919'
        e06_expire_voluntary_tx_info.bundleId                           = 'com.loki-project.loki-messenger'
        e06_expire_voluntary_tx_info.currency                           = 'AUD'
        e06_expire_voluntary_tx_info.environment                        = AppleEnvironment.SANDBOX
        e06_expire_voluntary_tx_info.expiresDate                        = 1759727970000
        e06_expire_voluntary_tx_info.inAppOwnershipType                 = AppleInAppOwnershipType.PURCHASED
        e06_expire_voluntary_tx_info.isUpgraded                         = None
        e06_expire_voluntary_tx_info.offerDiscountType                  = None
        e06_expire_voluntary_tx_info.offerIdentifier                    = None
        e06_expire_voluntary_tx_info.offerPeriod                        = None
        e06_expire_voluntary_tx_info.offerType                          = None
        e06_expire_voluntary_tx_info.originalPurchaseDate               = 1759301833000
        e06_expire_voluntary_tx_info.originalTransactionId              = '2000001024993299'
        e06_expire_voluntary_tx_info.price                              = 1990
        e06_expire_voluntary_tx_info.productId                          = 'com.getsession.org.pro_sub'
        e06_expire_voluntary_tx_info.purchaseDate                       = 1759727790000
        e06_expire_voluntary_tx_info.quantity                           = 1
        e06_expire_voluntary_tx_info.rawEnvironment                     = 'Sandbox'
        e06_expire_voluntary_tx_info.rawInAppOwnershipType              = 'PURCHASED'
        e06_expire_voluntary_tx_info.rawOfferDiscountType               = None
        e06_expire_voluntary_tx_info.rawOfferType                       = None
        e06_expire_voluntary_tx_info.rawRevocationReason                = None
        e06_expire_voluntary_tx_info.rawTransactionReason               = 'PURCHASE'
        e06_expire_voluntary_tx_info.rawType                            = 'Auto-Renewable Subscription'
        e06_expire_voluntary_tx_info.revocationDate                     = None
        e06_expire_voluntary_tx_info.revocationReason                   = None
        e06_expire_voluntary_tx_info.signedDate                         = 1759727985799
        e06_expire_voluntary_tx_info.storefront                         = 'AUS'
        e06_expire_voluntary_tx_info.storefrontId                       = '143460'
        e06_expire_voluntary_tx_info.subscriptionGroupIdentifier        = '21752814'
        e06_expire_voluntary_tx_info.transactionId                      = '2000001027701928'
        e06_expire_voluntary_tx_info.transactionReason                  = AppleTransactionReason.PURCHASE
        e06_expire_voluntary_tx_info.type                               = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        e06_expire_voluntary_tx_info.webOrderLineItemId                 = '2000000114202140'

        e06_expire_voluntary_decoded_notification                       = platform_apple.DecodedNotification(body=e06_expire_voluntary_body, tx_info=e06_expire_voluntary_tx_info, renewal_info=e06_expire_voluntary_renewal_info)

        # NOTE: Execute and test notifications
        err          = base.ErrorSink()
        master_key   = nacl.signing.SigningKey.generate()
        rotating_key = nacl.signing.SigningKey.generate()

        # NOTE: Witness 3 month subscription
        if 1:
            platform_apple.handle_notification(decoded_notification=e00_sub_to_3_months_decoded_notification, sql_conn=test.sql_conn, err=err)

            # NOTE: Check payment got added to the DB
            unredeemed_payment_list: list[backend.PaymentRow]                    = backend.get_unredeemed_payments_list(test.sql_conn)
            assert len(unredeemed_payment_list)                                 == 1
            assert unredeemed_payment_list[0].master_pkey                       == None
            assert unredeemed_payment_list[0].status                            == base.PaymentStatus.Unredeemed
            assert unredeemed_payment_list[0].plan                              == base.ProPlan.ThreeMonth
            assert unredeemed_payment_list[0].payment_provider                  == base.PaymentProvider.iOSAppStore
            assert unredeemed_payment_list[0].auto_renewing                     == True
            assert unredeemed_payment_list[0].unredeemed_unix_ts_ms             == e00_sub_to_3_months_tx_info.purchaseDate
            assert unredeemed_payment_list[0].redeemed_unix_ts_ms               == None
            assert unredeemed_payment_list[0].expiry_unix_ts_ms                 == e00_sub_to_3_months_tx_info.expiresDate
            assert unredeemed_payment_list[0].grace_period_duration_ms          == platform_apple.GRACE_PERIOD_DURATION_MS
            assert unredeemed_payment_list[0].platform_refund_expiry_unix_ts_ms == 0
            assert unredeemed_payment_list[0].revoked_unix_ts_ms                == None
            assert unredeemed_payment_list[0].apple.original_tx_id              == e00_sub_to_3_months_tx_info.originalTransactionId
            assert unredeemed_payment_list[0].apple.tx_id                       == e00_sub_to_3_months_tx_info.transactionId
            assert unredeemed_payment_list[0].apple.web_line_order_tx_id        == e00_sub_to_3_months_tx_info.webOrderLineItemId

            # NOTE: Then redeem the payment
            version = 0
            add_pro_payment_tx             = backend.AddProPaymentUserTransaction()
            add_pro_payment_tx.provider    = base.PaymentProvider.iOSAppStore
            add_pro_payment_tx.apple_tx_id = unredeemed_payment_list[0].apple.tx_id
            payment_hash_to_sign: bytes = backend.make_add_pro_payment_hash(version=version,
                                                                            master_pkey=master_key.verify_key,
                                                                            rotating_pkey=rotating_key.verify_key,
                                                                            payment_tx=add_pro_payment_tx)

            # NOTE: POST and get response
            response: werkzeug.test.TestResponse = test.flask_client.post(server.FLASK_ROUTE_ADD_PRO_PAYMENT, json={
                'version': version,
                'master_pkey':   bytes(master_key.verify_key).hex(),
                'rotating_pkey': bytes(rotating_key.verify_key).hex(),
                'master_sig':    bytes(master_key.sign(payment_hash_to_sign).signature).hex(),
                'rotating_sig':  bytes(rotating_key.sign(payment_hash_to_sign).signature).hex(),
                'payment_tx': {
                    'provider':    add_pro_payment_tx.provider.value,
                    'apple_tx_id': add_pro_payment_tx.apple_tx_id,
                }
            })

            # NOTE: Check payment got redeemed to the DB
            payment_list: list[backend.PaymentRow]                    = backend.get_payments_list(test.sql_conn)
            assert len(payment_list)                                 == 1
            assert payment_list[0].master_pkey                       == bytes(master_key.verify_key)
            assert payment_list[0].status                            == base.PaymentStatus.Redeemed
            assert payment_list[0].plan                              == base.ProPlan.ThreeMonth
            assert payment_list[0].payment_provider                  == base.PaymentProvider.iOSAppStore
            assert payment_list[0].auto_renewing                     == True
            assert payment_list[0].unredeemed_unix_ts_ms             == e00_sub_to_3_months_tx_info.purchaseDate
            assert payment_list[0].redeemed_unix_ts_ms               != None
            assert payment_list[0].expiry_unix_ts_ms                 == e00_sub_to_3_months_tx_info.expiresDate
            assert payment_list[0].grace_period_duration_ms          == platform_apple.GRACE_PERIOD_DURATION_MS
            assert payment_list[0].platform_refund_expiry_unix_ts_ms == 0
            assert payment_list[0].revoked_unix_ts_ms                == None
            assert payment_list[0].apple.original_tx_id              == e00_sub_to_3_months_tx_info.originalTransactionId
            assert payment_list[0].apple.tx_id                       == e00_sub_to_3_months_tx_info.transactionId
            assert payment_list[0].apple.web_line_order_tx_id        == e00_sub_to_3_months_tx_info.webOrderLineItemId


        # NOTE: "Upgrade" to 1 week subscription. Initially when we set up the Apple subscriptions,
        # 1 week was put at the top of the list, this makes it have a higher ranking than the 3
        # month subscription following it. This means that going to a 1 week subscription is
        # considered an "upgrade".
        if 1:
            platform_apple.handle_notification(decoded_notification=e01_upgrade_to_1wk_decoded_notification, sql_conn=test.sql_conn, err=err)

            # NOTE: An upgrade is applied immediately because the user pays on the spot to upgrade.
            # The old subscription should be revoked incase the user already redeemed it and the
            # new payment should be sitting in the unredeemed queue.

            # NOTE: Check the previous payment was refunded
            payment_list: list[backend.PaymentRow] = backend.get_payments_list(test.sql_conn)
            assert len(payment_list)                                 == 2
            assert payment_list[0].master_pkey                       == bytes(master_key.verify_key)
            assert payment_list[0].status                            == base.PaymentStatus.Revoked
            assert payment_list[0].plan                              == base.ProPlan.ThreeMonth
            assert payment_list[0].payment_provider                  == base.PaymentProvider.iOSAppStore
            assert payment_list[0].auto_renewing                     == False
            assert payment_list[0].unredeemed_unix_ts_ms             == e00_sub_to_3_months_tx_info.purchaseDate
            assert payment_list[0].redeemed_unix_ts_ms               != None
            assert payment_list[0].expiry_unix_ts_ms                 == e00_sub_to_3_months_tx_info.expiresDate
            assert payment_list[0].grace_period_duration_ms          == platform_apple.GRACE_PERIOD_DURATION_MS
            assert payment_list[0].platform_refund_expiry_unix_ts_ms == 0
            assert payment_list[0].revoked_unix_ts_ms                == e01_upgrade_to_1wk_tx_info.purchaseDate
            assert payment_list[0].apple.original_tx_id              == e00_sub_to_3_months_tx_info.originalTransactionId
            assert payment_list[0].apple.tx_id                       == e00_sub_to_3_months_tx_info.transactionId
            assert payment_list[0].apple.web_line_order_tx_id        == e00_sub_to_3_months_tx_info.webOrderLineItemId
            assert payment_list[0].revoked_unix_ts_ms                == e01_upgrade_to_1wk_tx_info.purchaseDate

            # NOTE: The previous payment was revoked, but it won't be in the revocation list because
            # a revocation's start time is rounded to the end of the day. So they won't show up if
            # the proof will expire before the revocation activates.
            #
            # In this example in particular, because we are using the apple sandbox testing
            # environment their timespans for subscriptions are greatly reduced to within the minute
            # range.
            #
            # We will test the other branches by modifying the timestamps, but for the reference
            # tests that use "real" sandbox data we will go with the flow.
            revocation_list: list[backend.RevocationRow]              = backend.get_revocations_list(test.sql_conn)
            assert len(revocation_list)                              == 0

            # NOTE: Check the new payment is in the unredeemed queue
            unredeemed_payment_list: list[backend.PaymentRow]                    = backend.get_unredeemed_payments_list(test.sql_conn)
            assert len(unredeemed_payment_list)                                 == 1
            assert unredeemed_payment_list[0].master_pkey                       == None
            assert unredeemed_payment_list[0].status                            == base.PaymentStatus.Unredeemed
            assert unredeemed_payment_list[0].plan                              == base.ProPlan.OneMonth
            assert unredeemed_payment_list[0].payment_provider                  == base.PaymentProvider.iOSAppStore
            assert unredeemed_payment_list[0].auto_renewing                     == True
            assert unredeemed_payment_list[0].unredeemed_unix_ts_ms             == e01_upgrade_to_1wk_tx_info.purchaseDate
            assert unredeemed_payment_list[0].redeemed_unix_ts_ms               == None
            assert unredeemed_payment_list[0].expiry_unix_ts_ms                 == e01_upgrade_to_1wk_tx_info.expiresDate
            assert unredeemed_payment_list[0].grace_period_duration_ms          == platform_apple.GRACE_PERIOD_DURATION_MS
            assert unredeemed_payment_list[0].platform_refund_expiry_unix_ts_ms == 0
            assert unredeemed_payment_list[0].revoked_unix_ts_ms                == None
            assert unredeemed_payment_list[0].apple.original_tx_id              == e01_upgrade_to_1wk_tx_info.originalTransactionId
            assert unredeemed_payment_list[0].apple.tx_id                       == e01_upgrade_to_1wk_tx_info.transactionId
            assert unredeemed_payment_list[0].apple.web_line_order_tx_id        == e01_upgrade_to_1wk_tx_info.webOrderLineItemId

            # NOTE: Check that the latest payment is the unredeemed payment
            assert payment_list[len(payment_list) - 1] == unredeemed_payment_list[0]

        if 1:
            platform_apple.handle_notification(decoded_notification=e02_disable_auto_renew_decoded_notification,           sql_conn=test.sql_conn, err=err)

            # NOTE: Check the payment was marked not auto-renewing
            unredeemed_payment_list: list[backend.PaymentRow]  = backend.get_unredeemed_payments_list(test.sql_conn)
            assert len(unredeemed_payment_list)               == 1
            assert unredeemed_payment_list[0].auto_renewing   == False

        # NOTE: A downgrade should be a no-op as it's queued to execute at the end of the billing
        # cycle, but it does implicitly mean that auto-renewing is turned back on.
        if 1:
            platform_apple.handle_notification(decoded_notification=e03_queue_downgrade_to_3_months_decoded_notification,  sql_conn=test.sql_conn, err=err)

            # NOTE: Check the new payment has remain unchanged
            unredeemed_payment_list: list[backend.PaymentRow]                    = backend.get_unredeemed_payments_list(test.sql_conn)
            assert len(unredeemed_payment_list)                                 == 1
            assert unredeemed_payment_list[0].master_pkey                       == None
            assert unredeemed_payment_list[0].status                            == base.PaymentStatus.Unredeemed
            assert unredeemed_payment_list[0].plan                              == base.ProPlan.OneMonth
            assert unredeemed_payment_list[0].payment_provider                  == base.PaymentProvider.iOSAppStore

            # NOTE: In this sequence, apparently, auto-renewing should be turned back on. The reason
            # for this is that since the user downgraded to 1wk plan which takes effect at the end
            # of the month, they are resuming their subscription with _another week_ after their
            # current billing cycle ends.
            #
            # So the auto-renewing flag on our side should be set true
            assert unredeemed_payment_list[0].auto_renewing                     == True

            assert unredeemed_payment_list[0].unredeemed_unix_ts_ms             == e01_upgrade_to_1wk_tx_info.purchaseDate
            assert unredeemed_payment_list[0].redeemed_unix_ts_ms               == None
            assert unredeemed_payment_list[0].expiry_unix_ts_ms                 == e01_upgrade_to_1wk_tx_info.expiresDate
            assert unredeemed_payment_list[0].grace_period_duration_ms          == platform_apple.GRACE_PERIOD_DURATION_MS
            assert unredeemed_payment_list[0].platform_refund_expiry_unix_ts_ms == 0
            assert unredeemed_payment_list[0].revoked_unix_ts_ms                == None
            assert unredeemed_payment_list[0].apple.original_tx_id              == e01_upgrade_to_1wk_tx_info.originalTransactionId
            assert unredeemed_payment_list[0].apple.tx_id                       == e01_upgrade_to_1wk_tx_info.transactionId
            assert unredeemed_payment_list[0].apple.web_line_order_tx_id        == e01_upgrade_to_1wk_tx_info.webOrderLineItemId

        # TODO: We need to check that the correct proofs are revoked. This is not done yet in Apple

        # NOTE: Cancelling a downgrade means that the queued downgrade to 3 months is undone. We
        # remain on the 1wk plan
        if 1:
            platform_apple.handle_notification(decoded_notification=e04_cancel_downgrade_to_3_months_decoded_notification, sql_conn=test.sql_conn, err=err)

            # NOTE: Check that the initial 3 month subscription remains refunded (e.g. unchanged)
            payment_list: list[backend.PaymentRow] = backend.get_payments_list(test.sql_conn)
            assert len(payment_list) == 2
            assert payment_list[0].master_pkey                       == bytes(master_key.verify_key)
            assert payment_list[0].status                            == base.PaymentStatus.Revoked
            assert payment_list[0].plan                              == base.ProPlan.ThreeMonth
            assert payment_list[0].payment_provider                  == base.PaymentProvider.iOSAppStore
            assert payment_list[0].auto_renewing                     == False
            assert payment_list[0].unredeemed_unix_ts_ms             == e00_sub_to_3_months_tx_info.purchaseDate
            assert payment_list[0].redeemed_unix_ts_ms               != None
            assert payment_list[0].expiry_unix_ts_ms                 == e00_sub_to_3_months_tx_info.expiresDate
            assert payment_list[0].grace_period_duration_ms          == platform_apple.GRACE_PERIOD_DURATION_MS
            assert payment_list[0].platform_refund_expiry_unix_ts_ms == 0
            assert payment_list[0].revoked_unix_ts_ms                == e01_upgrade_to_1wk_tx_info.purchaseDate
            assert payment_list[0].apple.original_tx_id              == e00_sub_to_3_months_tx_info.originalTransactionId
            assert payment_list[0].apple.tx_id                       == e00_sub_to_3_months_tx_info.transactionId
            assert payment_list[0].apple.web_line_order_tx_id        == e00_sub_to_3_months_tx_info.webOrderLineItemId

            # NOTE: Check that the 1 week plan remains unchanged
            unredeemed_payment_list: list[backend.PaymentRow]                    = backend.get_unredeemed_payments_list(test.sql_conn)
            assert len(unredeemed_payment_list)                                 == 1
            assert unredeemed_payment_list[0].master_pkey                       == None
            assert unredeemed_payment_list[0].status                            == base.PaymentStatus.Unredeemed
            assert unredeemed_payment_list[0].plan                              == base.ProPlan.OneMonth
            assert unredeemed_payment_list[0].payment_provider                  == base.PaymentProvider.iOSAppStore
            assert unredeemed_payment_list[0].auto_renewing                     == True
            assert unredeemed_payment_list[0].unredeemed_unix_ts_ms             == e01_upgrade_to_1wk_tx_info.purchaseDate
            assert unredeemed_payment_list[0].redeemed_unix_ts_ms               == None
            assert unredeemed_payment_list[0].expiry_unix_ts_ms                 == e01_upgrade_to_1wk_tx_info.expiresDate
            assert unredeemed_payment_list[0].grace_period_duration_ms          == platform_apple.GRACE_PERIOD_DURATION_MS
            assert unredeemed_payment_list[0].platform_refund_expiry_unix_ts_ms == 0
            assert unredeemed_payment_list[0].revoked_unix_ts_ms                == None
            assert unredeemed_payment_list[0].apple.original_tx_id              == e01_upgrade_to_1wk_tx_info.originalTransactionId
            assert unredeemed_payment_list[0].apple.tx_id                       == e01_upgrade_to_1wk_tx_info.transactionId
            assert unredeemed_payment_list[0].apple.web_line_order_tx_id        == e01_upgrade_to_1wk_tx_info.webOrderLineItemId

        # NOTE: Disable auto renew, flag should be turned false for the 1 week plan payment
        if 1:
            platform_apple.handle_notification(decoded_notification=e05_disable_auto_renew_decoded_notification, sql_conn=test.sql_conn, err=err)

            # NOTE: Check the payment was marked not auto-renewing
            unredeemed_payment_list: list[backend.PaymentRow]  = backend.get_unredeemed_payments_list(test.sql_conn)
            assert len(unredeemed_payment_list)               == 1
            assert unredeemed_payment_list[0].auto_renewing   == False

        # NOTE: Expire the subscription
        if 1:
            platform_apple.handle_notification(decoded_notification=e06_expire_voluntary_decoded_notification,   sql_conn=test.sql_conn, err=err)

            # NOTE: This is a no-op, but in this test we haven't advanced time past the expiry yet
            # so actually the subscription should still be marked unredeemed in the database hence
            # check that the 1 week plan remains unchanged
            unredeemed_payment_list: list[backend.PaymentRow]                    = backend.get_unredeemed_payments_list(test.sql_conn)
            assert len(unredeemed_payment_list)                                 == 1
            assert unredeemed_payment_list[0].master_pkey                       == None
            assert unredeemed_payment_list[0].status                            == base.PaymentStatus.Unredeemed
            assert unredeemed_payment_list[0].plan                              == base.ProPlan.OneMonth
            assert unredeemed_payment_list[0].payment_provider                  == base.PaymentProvider.iOSAppStore
            assert unredeemed_payment_list[0].auto_renewing                     == False
            assert unredeemed_payment_list[0].unredeemed_unix_ts_ms             == e01_upgrade_to_1wk_tx_info.purchaseDate
            assert unredeemed_payment_list[0].redeemed_unix_ts_ms               == None
            assert unredeemed_payment_list[0].expiry_unix_ts_ms                 == e01_upgrade_to_1wk_tx_info.expiresDate
            assert unredeemed_payment_list[0].grace_period_duration_ms          == platform_apple.GRACE_PERIOD_DURATION_MS
            assert unredeemed_payment_list[0].platform_refund_expiry_unix_ts_ms == 0
            assert unredeemed_payment_list[0].revoked_unix_ts_ms                == None
            assert unredeemed_payment_list[0].apple.original_tx_id              == e01_upgrade_to_1wk_tx_info.originalTransactionId
            assert unredeemed_payment_list[0].apple.tx_id                       == e01_upgrade_to_1wk_tx_info.transactionId
            assert unredeemed_payment_list[0].apple.web_line_order_tx_id        == e01_upgrade_to_1wk_tx_info.webOrderLineItemId

        assert not err.has(), err.msg_list



def test_google_platform_handle_notification(monkeypatch):
    # Setup DB
    err                       = base.ErrorSink()
    db: backend.SetupDBResult = backend.setup_db(path="file:test_server_db_google_test?mode=memory&cache=shared", uri=True, err=err)
    
    assert len(err.msg_list) == 0, f'{err.msg_list}'
    assert db.sql_conn

    _ = platform_google.init(sql_conn                = db.sql_conn,
                             project_name            = 'loki-5a81e',
                             package_name            = 'network.loki.messenger',
                             subscription_name       = 'session-pro-sub',
                             subscription_product_id = 'session_pro',
                             app_credentials_path    = None)
    
    # Setup local flask instance
    flask_app:    flask.Flask     = server.init(testing_mode=True,
                                                db_path=db.path,
                                                db_path_is_uri=True,
                                                server_x25519_skey=db.runtime.backend_key.to_curve25519_private_key())

    flask_client: werkzeug.Client = flask_app.test_client()
    
    master_key                      = nacl.signing.SigningKey.generate()
    rotating_key                    = nacl.signing.SigningKey.generate()

    def get_pro_status():
        unix_ts_ms: int                 = int(time.time() * 1000)
        version:      int   = 0
        history:      bool  = True
        hash_to_sign: bytes = server.make_get_all_payments_hash(version=version, master_pkey=master_key.verify_key, unix_ts_ms=unix_ts_ms, history=history)
        request_body={'version':     version,
                      'master_pkey': bytes(master_key.verify_key).hex(),
                      'master_sig':  bytes(master_key.sign(hash_to_sign).signature).hex(),
                      'unix_ts_ms':  unix_ts_ms,
                      'history':     history}
        response: werkzeug.test.TestResponse = flask_client.post(server.FLASK_ROUTE_GET_PRO_STATUS, json=request_body)

        return response.json

    one_month_purchase = (# PURCHASE 1-month
{'version': '1.0', 'packageName': 'network.loki.messenger', 'eventTimeMillis': '1759723091078', 'subscriptionNotification': {'version': '1.0', 'notificationType': 4, 'purchaseToken': 'lgmmicancjpmkconmddnaicb.AO-J1OyZa0o1Xez6T7kCcaIpqyIKzt5n1D_cTEFQhHJzVKw4INw2cMmckgE-ME0DgO1xJuFAYDuiYuM-Sy87HLQ8qvitpiMGrMnu1iL_-yvAYc4CoAx8u_Q', 'subscriptionId': 'session_pro'}},
{'kind': 'androidpublisher#subscriptionPurchaseV2', 'startTime': '2025-10-06T03:58:10.981Z', 'regionCode': 'AU', 'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE', 'latestOrderId': 'GPA.3354-3745-5570-25336', 'testPurchase': {}, 'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING', 'lineItems': [{'productId': 'session_pro', 'expiryTime': '2025-10-06T04:03:10.613Z', 'autoRenewingPlan': {'autoRenewEnabled': True, 'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}}, 'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']}, 'latestSuccessfulOrderId': 'GPA.3354-3745-5570-25336'}]})
    one_month_cancel =(# Cancel no reason 1-month
{'version': '1.0', 'packageName': 'network.loki.messenger', 'eventTimeMillis': '1759723188437', 'subscriptionNotification': {'version': '1.0', 'notificationType': 3, 'purchaseToken': 'lgmmicancjpmkconmddnaicb.AO-J1OyZa0o1Xez6T7kCcaIpqyIKzt5n1D_cTEFQhHJzVKw4INw2cMmckgE-ME0DgO1xJuFAYDuiYuM-Sy87HLQ8qvitpiMGrMnu1iL_-yvAYc4CoAx8u_Q', 'subscriptionId': 'session_pro'}},
{'kind': 'androidpublisher#subscriptionPurchaseV2', 'startTime': '2025-10-06T03:58:10.981Z', 'regionCode': 'AU', 'subscriptionState': 'SUBSCRIPTION_STATE_CANCELED', 'latestOrderId': 'GPA.3354-3745-5570-25336', 'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-06T03:59:48.074Z'}}, 'testPurchase': {}, 'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING', 'lineItems': [{'productId': 'session_pro', 'expiryTime': '2025-10-06T04:03:10.613Z', 'autoRenewingPlan': {'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}}, 'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']}, 'latestSuccessfulOrderId': 'GPA.3354-3745-5570-25336'}]})
    one_month_resub =(# Resubscribe after cancel but before expiry
{'version': '1.0', 'packageName': 'network.loki.messenger', 'eventTimeMillis': '1759723199349', 'subscriptionNotification': {'version': '1.0', 'notificationType': 7, 'purchaseToken': 'lgmmicancjpmkconmddnaicb.AO-J1OyZa0o1Xez6T7kCcaIpqyIKzt5n1D_cTEFQhHJzVKw4INw2cMmckgE-ME0DgO1xJuFAYDuiYuM-Sy87HLQ8qvitpiMGrMnu1iL_-yvAYc4CoAx8u_Q', 'subscriptionId': 'session_pro'}},
{'kind': 'androidpublisher#subscriptionPurchaseV2', 'startTime': '2025-10-06T03:58:10.981Z', 'regionCode': 'AU', 'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE', 'latestOrderId': 'GPA.3354-3745-5570-25336', 'testPurchase': {}, 'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING', 'lineItems': [{'productId': 'session_pro', 'expiryTime': '2025-10-06T04:03:10.613Z', 'autoRenewingPlan': {'autoRenewEnabled': True, 'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}}, 'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']}, 'latestSuccessfulOrderId': 'GPA.3354-3745-5570-25336'}]})
    one_month_refund =(# Revoked before expiry
{'version': '1.0', 'packageName': 'network.loki.messenger', 'eventTimeMillis': '1759723392088', 'subscriptionNotification': {'version': '1.0', 'notificationType': 12, 'purchaseToken': 'lgmmicancjpmkconmddnaicb.AO-J1OyZa0o1Xez6T7kCcaIpqyIKzt5n1D_cTEFQhHJzVKw4INw2cMmckgE-ME0DgO1xJuFAYDuiYuM-Sy87HLQ8qvitpiMGrMnu1iL_-yvAYc4CoAx8u_Q', 'subscriptionId': 'session_pro'}},
{'kind': 'androidpublisher#subscriptionPurchaseV2', 'startTime': '2025-10-06T03:58:10.981Z', 'regionCode': 'AU', 'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED', 'latestOrderId': 'GPA.3354-3745-5570-25336', 'canceledStateContext': {'systemInitiatedCancellation': {}}, 'testPurchase': {}, 'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING', 'lineItems': [{'productId': 'session_pro', 'expiryTime': '2025-10-06T04:03:11.808Z', 'autoRenewingPlan': {'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}}, 'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']}, 'latestSuccessfulOrderId': 'GPA.3354-3745-5570-25336'}]})
    

    monkeypatch.setattr(
        "platform_google_api.fetch_subscription_details_for_base_plan_id",
        lambda *args, **kwargs: SubscriptionProductDetails(
            billing_period=GoogleDuration("P30D", err),
            grace_period=GoogleDuration("P2D", err)
        )
    )

    monkeypatch.setattr(
        "platform_google_api.subscription_v1_acknowledge",
        lambda *args, **kwargs: None
    )

    def test_notification(scenario: tuple[base.JSONObject, base.JSONObject]):
        err = base.ErrorSink()
        err_tx = backend.UserErrorTransaction()

        notification, raw_state = scenario
        current_state = platform_google_api.parse_get_subscription_v2_response(raw_state, err)
        monkeypatch.setattr(
            "platform_google_api.fetch_subscription_v2_details",
            lambda *args, **kwargs: current_state
        )

        event_time_ms_str = notification['eventTimeMillis']
        assert isinstance(event_time_ms_str, str)
        event_ms = int(event_time_ms_str)
        now_ms = event_ms - 100

        purchase_token = None
        if "subscriptionNotification" in notification:
            purchase_token = notification["subscriptionNotification"]["purchaseToken"]
        elif "voidedNotification" in notification:
            purchase_token = notification["voidedNotification"]["purchaseToken"]

        assert isinstance(purchase_token, str)
        assert db.sql_conn
        handle_notification(notification, err_tx, db.sql_conn, err)
        assert not err.has()
        return current_state, purchase_token, event_ms

    assert len(backend.get_unredeemed_payments_list(db.sql_conn)) == 0
    
    # Subscribe 1month
    current_state, purchase_token, event_ms = test_notification(one_month_purchase)
    assert current_state is not None
    order_id = current_state.line_items[0].latest_successful_order_id
    expiry_time_unix_ms = current_state.line_items[0].expiry_time.unix_milliseconds
    platform_refund_expiry_unix_ts_ms = event_ms + base.MILLISECONDS_IN_DAY * 2 
    
    assert order_id is not None
    assert purchase_token is not None

    unredeemed_payments = backend.get_unredeemed_payments_list(db.sql_conn)
    assert len(unredeemed_payments) == 1
    
    unredeemed_payment = unredeemed_payments[0]
    assert isinstance(unredeemed_payment, backend.PaymentRow)

    assert unredeemed_payment.master_pkey == None
    assert unredeemed_payment.status == base.PaymentStatus.Unredeemed
    assert unredeemed_payment.plan == base.ProPlan.OneMonth
    assert unredeemed_payment.payment_provider == base.PaymentProvider.GooglePlayStore
    assert unredeemed_payment.redeemed_unix_ts_ms == None
    assert unredeemed_payment.expiry_unix_ts_ms ==expiry_time_unix_ms
    assert unredeemed_payment.grace_period_duration_ms == 0
    assert unredeemed_payment.platform_refund_expiry_unix_ts_ms == platform_refund_expiry_unix_ts_ms
    assert unredeemed_payment.revoked_unix_ts_ms == None
    assert unredeemed_payment.apple == backend.AppleTransaction()
    assert unredeemed_payment.google_payment_token == purchase_token
    assert unredeemed_payment.google_order_id == order_id

    # Add payment (claim unredeemed)
    version: int                            = 0
    add_pro_payment_tx                      = backend.AddProPaymentUserTransaction()
    add_pro_payment_tx.provider             = unredeemed_payment.payment_provider
    add_pro_payment_tx.google_payment_token = purchase_token

    payment_hash_to_sign: bytes = backend.make_add_pro_payment_hash(version=version,
                                                                    master_pkey=master_key.verify_key,
                                                                    rotating_pkey=rotating_key.verify_key,
                                                                    payment_tx=add_pro_payment_tx)

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
        }
    response: werkzeug.test.TestResponse = flask_client.post(server.FLASK_ROUTE_ADD_PRO_PAYMENT, json=request_body)

    unredeemed_payments = backend.get_unredeemed_payments_list(db.sql_conn)
    assert len(unredeemed_payments) == 0

    payments = backend.get_payments_list(sql_conn=db.sql_conn)
    assert len(payments) == 1

    payment = payments[0]
    assert isinstance(payment, backend.PaymentRow)
    assert payment.master_pkey == bytes(master_key.verify_key)
    assert payment.status == base.PaymentStatus.Redeemed
    assert payment.plan == base.ProPlan.OneMonth
    assert payment.payment_provider == base.PaymentProvider.GooglePlayStore
    assert payment.redeemed_unix_ts_ms is not None and payment.redeemed_unix_ts_ms == base.round_unix_ts_ms_to_next_day(int(time.time() * 1000))
    assert payment.expiry_unix_ts_ms == unredeemed_payment.expiry_unix_ts_ms
    assert payment.grace_period_duration_ms == 0
    assert payment.platform_refund_expiry_unix_ts_ms == platform_refund_expiry_unix_ts_ms
    assert payment.revoked_unix_ts_ms == None
    assert payment.apple == backend.AppleTransaction()
    assert payment.google_payment_token == purchase_token
    assert payment.google_order_id == order_id

    users = backend.get_users_list(sql_conn=db.sql_conn)
    assert len(users) == 1
    user = users[0]
    assert isinstance(user, backend.UserRow)
    assert user.master_pkey == bytes(master_key.verify_key)
    assert user.gen_index == 0
    assert user.expiry_unix_ts_ms == unredeemed_payment.expiry_unix_ts_ms

    status = get_pro_status()
    assert status is not None
    result = base.json_dict_require_obj(status, "result", err)
    res_auto_renewing = base.json_dict_require_bool(result, "auto_renewing", err)
    res_latest_expiry_unix_ts = base.json_dict_require_int(result, "expiry_unix_ts_ms", err)
    res_pro_status = base.json_dict_require_int_coerce_to_enum(result, "status", server.UserProStatus, err)
    res_items = base.json_dict_require_array(result, "items", err)
    assert not err.has()
    assert res_auto_renewing == True
    assert res_latest_expiry_unix_ts == expiry_time_unix_ms
    assert res_pro_status == server.UserProStatus.Active
    assert len(res_items) == 1
    item = res_items[0]

    item_expiry_unix_ts = base.json_dict_require_int(item, "expiry_unix_ts_ms", err)
    item_order_id = base.json_dict_require_str(item, "google_order_id", err)
    item_payment_token = base.json_dict_require_str(item, "google_payment_token", err)
    item_grace_duration_ms = base.json_dict_require_int(item, "grace_period_duration_ms", err)
    item_payment_provider = base.json_dict_require_int_coerce_to_enum(item, "payment_provider", base.PaymentProvider, err)
    item_platform_refund_expiry_unix_ts_ms = base.json_dict_require_int(item, "platform_refund_expiry_unix_ts_ms", err)
    item_redeemed_unix_ts_ms = base.json_dict_require_int(item, "redeemed_unix_ts_ms", err)
    item_refunded_unix_ts_ms = base.json_dict_require_int(item, "revoked_unix_ts_ms", err)
    item_status = base.json_dict_require_int_coerce_to_enum(item, "status", base.PaymentStatus, err)
    assert not err.has()
    assert item_expiry_unix_ts == expiry_time_unix_ms
    assert item_order_id == order_id
    assert item_payment_token == purchase_token
    assert item_grace_duration_ms == 0
    assert item_payment_provider == base.PaymentProvider.GooglePlayStore
    assert item_platform_refund_expiry_unix_ts_ms == platform_refund_expiry_unix_ts_ms
    assert item_redeemed_unix_ts_ms == payment.redeemed_unix_ts_ms
    assert item_refunded_unix_ts_ms == 0
    assert item_status == base.PaymentStatus.Redeemed

    # Cancel 1-month
    current_state, purchase_token, now_ms = test_notification(one_month_cancel)

    status = get_pro_status()
    assert status is not None
    result = base.json_dict_require_obj(status, "result", err)
    res_auto_renewing = base.json_dict_require_bool(result, "auto_renewing", err)
    res_latest_expiry_unix_ts = base.json_dict_require_int(result, "expiry_unix_ts_ms", err)
    res_pro_status = base.json_dict_require_int_coerce_to_enum(result, "status", server.UserProStatus, err)
    res_items = base.json_dict_require_array(result, "items", err)
    assert not err.has()
    assert res_auto_renewing == False
    assert res_latest_expiry_unix_ts == expiry_time_unix_ms
    assert res_pro_status == server.UserProStatus.Active
    assert len(res_items) == 1
    item = res_items[0]

    item_expiry_unix_ts = base.json_dict_require_int(item, "expiry_unix_ts_ms", err)
    item_order_id = base.json_dict_require_str(item, "google_order_id", err)
    item_payment_token = base.json_dict_require_str(item, "google_payment_token", err)
    item_grace_duration_ms = base.json_dict_require_int(item, "grace_period_duration_ms", err)
    item_payment_provider = base.json_dict_require_int_coerce_to_enum(item, "payment_provider", base.PaymentProvider, err)
    item_platform_refund_expiry_unix_ts_ms = base.json_dict_require_int(item, "platform_refund_expiry_unix_ts_ms", err)
    item_redeemed_unix_ts_ms = base.json_dict_require_int(item, "redeemed_unix_ts_ms", err)
    item_refunded_unix_ts_ms = base.json_dict_require_int(item, "revoked_unix_ts_ms", err)
    item_status = base.json_dict_require_int_coerce_to_enum(item, "status", base.PaymentStatus, err)
    assert not err.has()
    assert item_expiry_unix_ts == expiry_time_unix_ms
    assert item_order_id == order_id
    assert item_payment_token == purchase_token
    assert item_grace_duration_ms == 0
    assert item_payment_provider == base.PaymentProvider.GooglePlayStore
    assert item_platform_refund_expiry_unix_ts_ms == platform_refund_expiry_unix_ts_ms
    assert item_redeemed_unix_ts_ms == payment.redeemed_unix_ts_ms
    assert item_refunded_unix_ts_ms == 0
    assert item_status == base.PaymentStatus.Redeemed

    # Resubscribe 1-month
    current_state, purchase_token, now_ms = test_notification(one_month_resub)

    status = get_pro_status()
    assert status is not None
    result = base.json_dict_require_obj(status, "result", err)
    res_auto_renewing = base.json_dict_require_bool(result, "auto_renewing", err)
    res_latest_expiry_unix_ts = base.json_dict_require_int(result, "expiry_unix_ts_ms", err)
    res_pro_status = base.json_dict_require_int_coerce_to_enum(result, "status", server.UserProStatus, err)
    res_items = base.json_dict_require_array(result, "items", err)
    assert not err.has()
    assert res_auto_renewing == True
    assert res_latest_expiry_unix_ts == expiry_time_unix_ms
    assert res_pro_status == server.UserProStatus.Active
    assert len(res_items) == 1
    item = res_items[0]

    item_expiry_unix_ts = base.json_dict_require_int(item, "expiry_unix_ts_ms", err)
    item_order_id = base.json_dict_require_str(item, "google_order_id", err)
    item_payment_token = base.json_dict_require_str(item, "google_payment_token", err)
    item_grace_duration_ms = base.json_dict_require_int(item, "grace_period_duration_ms", err)
    item_payment_provider = base.json_dict_require_int_coerce_to_enum(item, "payment_provider", base.PaymentProvider, err)
    item_platform_refund_expiry_unix_ts_ms = base.json_dict_require_int(item, "platform_refund_expiry_unix_ts_ms", err)
    item_redeemed_unix_ts_ms = base.json_dict_require_int(item, "redeemed_unix_ts_ms", err)
    item_refunded_unix_ts_ms = base.json_dict_require_int(item, "revoked_unix_ts_ms", err)
    item_status = base.json_dict_require_int_coerce_to_enum(item, "status", base.PaymentStatus, err)
    assert not err.has()
    assert item_expiry_unix_ts == expiry_time_unix_ms
    assert item_order_id == order_id
    assert item_payment_token == purchase_token
    assert item_grace_duration_ms == 0
    assert item_payment_provider == base.PaymentProvider.GooglePlayStore
    assert item_platform_refund_expiry_unix_ts_ms == platform_refund_expiry_unix_ts_ms
    assert item_redeemed_unix_ts_ms == payment.redeemed_unix_ts_ms
    assert item_refunded_unix_ts_ms == 0
    assert item_status == base.PaymentStatus.Redeemed

    # Refund before expiry
    current_state, purchase_token, now_ms = test_notification(one_month_refund)
    
    status = get_pro_status()
    assert status is not None
    result = base.json_dict_require_obj(status, "result", err)
    res_auto_renewing = base.json_dict_require_bool(result, "auto_renewing", err)
    res_latest_expiry_unix_ts = base.json_dict_require_int(result, "expiry_unix_ts_ms", err)
    res_pro_status = base.json_dict_require_int_coerce_to_enum(result, "status", server.UserProStatus, err)
    res_items = base.json_dict_require_array(result, "items", err)
    assert not err.has()
    assert res_auto_renewing == False
    assert res_latest_expiry_unix_ts == expiry_time_unix_ms
    assert res_pro_status == server.UserProStatus.Expired
    assert len(res_items) == 1
    item = res_items[0]

    item_expiry_unix_ts = base.json_dict_require_int(item, "expiry_unix_ts_ms", err)
    item_order_id = base.json_dict_require_str(item, "google_order_id", err)
    item_payment_token = base.json_dict_require_str(item, "google_payment_token", err)
    item_grace_duration_ms = base.json_dict_require_int(item, "grace_period_duration_ms", err)
    item_payment_provider = base.json_dict_require_int_coerce_to_enum(item, "payment_provider", base.PaymentProvider, err)
    item_platform_refund_expiry_unix_ts_ms = base.json_dict_require_int(item, "platform_refund_expiry_unix_ts_ms", err)
    item_redeemed_unix_ts_ms = base.json_dict_require_int(item, "redeemed_unix_ts_ms", err)
    item_refunded_unix_ts_ms = base.json_dict_require_int(item, "revoked_unix_ts_ms", err)
    item_status = base.json_dict_require_int_coerce_to_enum(item, "status", base.PaymentStatus, err)
    assert not err.has()
    assert item_expiry_unix_ts == expiry_time_unix_ms
    assert item_order_id == order_id
    assert item_payment_token == purchase_token
    assert item_grace_duration_ms == 0
    assert item_payment_provider == base.PaymentProvider.GooglePlayStore
    assert item_platform_refund_expiry_unix_ts_ms == platform_refund_expiry_unix_ts_ms
    assert item_redeemed_unix_ts_ms == payment.redeemed_unix_ts_ms
    assert item_refunded_unix_ts_ms == now_ms
    assert item_status == base.PaymentStatus.Revoked
