'''
This file is the HTTP layer which declares the functions that serve the routes
for interacting with the Session Pro Backend. These routes are registered
onto a Flask application which enable the endpoints for the server.

The role of this layer is to intercept and sanitize the HTTP request, extracting
the JSON into valid, strongly typed (to Python's best ability) types that can be
passed into the backend.

The backend is responsible for further validation of the request such as
signature verification and consistency against the state of the DB. If
successful the result is returned back to this layer and piped back to the user
in the HTTP response.
'''

import math
import flask
import typing
import time
import nacl.signing
import nacl.bindings
import nacl.public
import collections.abc
import hashlib
import json

import base
import backend
from vendor import onion_req

class GetJSONFromFlaskRequest:
    json:    dict[str, typing.Any] = {}
    err_msg: str                   = ''

# Keys stored in the flask app config dictionary that can be retrieved within
# a request to get the path to the SQLite DB to load and use for that request.
CONFIG_DB_PATH_KEY               = 'session_pro_backend_db_path'
CONFIG_DB_PATH_IS_URI_KEY        = 'session_pro_backend_db_path_is_uri'

# Name of the endpoints exposed on the server
ROUTE_GET_PRO_SUBSCRIPTION_PROOF = '/get_pro_subscription_proof'
ROUTE_GET_REVOCATIONS            = '/get_revocations'
ROUTE_ADD_PAYMENT                = '/add_payment'
ROUTE_GET_PAYMENTS               = '/get_payments'

# How many seconds can the timestamp in the get all payments route can drift
# from the current server's timestamp before it's flat out rejected
GET_ALL_PAYMENTS_MAX_TIMESTAMP_DELTA_S = 5

# The object containing routes that you register onto a Flask app to turn it
# into an app that accepts Session Pro Backend client requests.
flask_blueprint = flask.Blueprint('session-pro-backend-blueprint', __name__)

def html_bad_response(http_status: int, msg: str | list[str]) -> flask.Response:
    result        = flask.jsonify({ 'status': http_status, 'msg': msg})
    result.status = http_status
    return result

def html_good_response(dict_result: typing.Any) -> flask.Response:
    result = flask.jsonify({ 'status': 200, 'result': dict_result})
    return result

def get_json_from_flask_request(request: flask.Request) -> GetJSONFromFlaskRequest:
    # Get JSON from request
    result: GetJSONFromFlaskRequest = GetJSONFromFlaskRequest()
    try:
        json_dict = typing.cast(dict[str, typing.Any] | None, json.loads(request.data))
        if json_dict is None:
            result.err_msg = "JSON failed to be parsed"
        else:
            result.json = json_dict
    except Exception as e:
        result.err_msg = str(e)

    return result

def make_get_all_payments_hash(version: int, master_pkey: nacl.signing.VerifyKey, timestamp: int, page: int) -> bytes:
    hasher: hashlib.blake2b = backend.make_blake2b_hasher()
    hasher.update(version.to_bytes(length=1, byteorder='little'))
    hasher.update(bytes(master_pkey))
    hasher.update(timestamp.to_bytes(length=8, byteorder='little'))
    hasher.update(page.to_bytes(length=4, byteorder='little'))
    result: bytes = hasher.digest()
    return result

def init(testing_mode: bool, db_path: str, db_path_is_uri: bool, server_x25519_skey: nacl.public.PrivateKey) -> flask.Flask:
    result                                                      = flask.Flask(__name__)
    result.config['TESTING']                                    = testing_mode
    result.config[CONFIG_DB_PATH_KEY]                           = db_path
    result.config[CONFIG_DB_PATH_IS_URI_KEY]                    = db_path_is_uri
    result.config[onion_req.FLASK_CONFIG_ONION_REQ_X25519_SKEY] = server_x25519_skey
    result.register_blueprint(flask_blueprint)
    result.register_blueprint(onion_req.flask_blueprint_v4)
    return result

@flask_blueprint.route(ROUTE_ADD_PAYMENT, methods=['POST'])
def add_payment():
    # Get JSON from request
    get: GetJSONFromFlaskRequest = get_json_from_flask_request(flask.request)
    if len(get.err_msg):
        return html_bad_response(400, get.err_msg)

    # Extract values from JSON
    err                = base.ErrorSink()
    version:       int = base.dict_require(d=get.json, key='version',       default_val=0,  err_msg="Missing version from body",             err=err)
    master_pkey:   str = base.dict_require(d=get.json, key='master_pkey',   default_val='', err_msg="Missing master public key from body",   err=err)
    rotating_pkey: str = base.dict_require(d=get.json, key='rotating_pkey', default_val='', err_msg="Missing rotating public key from body", err=err)
    payment_token: str = base.dict_require(d=get.json, key='payment_token', default_val='', err_msg="Missing payment token from body",       err=err)
    master_sig:    str = base.dict_require(d=get.json, key='master_sig',    default_val='', err_msg="Missing master signature from body",    err=err)
    rotating_sig:  str = base.dict_require(d=get.json, key='rotating_sig',  default_val='', err_msg="Missing rotating signature from body",  err=err)
    if len(err.msg_list):
        return html_bad_response(400, err.msg_list)

    # Parse and validate values
    if version != 0:
        err.msg_list.append(f'Unrecognised version passed: {version}')
        nacl.signing.SigningKey
    master_pkey_bytes   = base.hex_to_bytes(hex=master_pkey,   label='Master public key',      hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2, err=err)
    rotating_pkey_bytes = base.hex_to_bytes(hex=rotating_pkey, label='Rotating public key',    hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2, err=err)
    payment_token_bytes = base.hex_to_bytes(hex=payment_token, label='Payment token',          hex_len=backend.BLAKE2B_DIGEST_SIZE * 2,              err=err)
    master_sig_bytes    = base.hex_to_bytes(hex=master_sig,    label='Master key signature',   hex_len=nacl.bindings.crypto_sign_BYTES * 2,          err=err)
    rotating_sig_bytes  = base.hex_to_bytes(hex=rotating_sig,  label='Rotating key signature', hex_len=nacl.bindings.crypto_sign_BYTES * 2,          err=err)
    if len(err.msg_list):
        return html_bad_response(400, err.msg_list)

    # Submit the payment to the DB
    with open_db_from_flask_request_context(flask.current_app) as db:
        creation_unix_ts_s: int = base.round_unix_ts_to_next_day(int(time.time()))
        proof                   = backend.add_payment(sql_conn           = db.sql_conn,
                                                      version            = version,
                                                      signing_key        = db.runtime.backend_key,
                                                      creation_unix_ts_s = creation_unix_ts_s,
                                                      master_pkey        = nacl.signing.VerifyKey(master_pkey_bytes),
                                                      rotating_pkey      = nacl.signing.VerifyKey(rotating_pkey_bytes),
                                                      payment_token_hash = payment_token_bytes,
                                                      master_sig         = master_sig_bytes,
                                                      rotating_sig       = rotating_sig_bytes,
                                                      err                = err)

    result = html_bad_response(400, err.msg_list) if len(err.msg_list) else html_good_response(proof.to_dict())
    return result

def open_db_from_flask_request_context(flask_app: flask.Flask) -> backend.OpenDBAtPath:
    assert CONFIG_DB_PATH_KEY        in flask.current_app.config
    assert CONFIG_DB_PATH_IS_URI_KEY in flask.current_app.config
    db_path        = typing.cast(str, flask_app.config[CONFIG_DB_PATH_KEY])
    db_path_is_uri = typing.cast(bool, flask_app.config[CONFIG_DB_PATH_IS_URI_KEY])
    result         = backend.OpenDBAtPath(db_path, db_path_is_uri)
    return result

@flask_blueprint.route(ROUTE_GET_PRO_SUBSCRIPTION_PROOF, methods=['POST'])
def get_pro_subscription_proof() -> flask.Response:
    # Get JSON from request
    get: GetJSONFromFlaskRequest = get_json_from_flask_request(flask.request)
    if len(get.err_msg):
        return html_bad_response(400, get.err_msg)

    # Extract values from JSON
    err                = base.ErrorSink()
    version:       int = base.dict_require(d=get.json, key='version',       default_val=0,  err_msg="Missing version from body",             err=err)
    master_pkey:   str = base.dict_require(d=get.json, key='master_pkey',   default_val='', err_msg="Missing master public key from body",   err=err)
    rotating_pkey: str = base.dict_require(d=get.json, key='rotating_pkey', default_val='', err_msg="Missing rotating public key from body", err=err)
    unix_ts_s:     int = base.dict_require(d=get.json, key='unix_ts_s',     default_val=0,  err_msg="Missing unix timestamp from body",      err=err)
    master_sig:    str = base.dict_require(d=get.json, key='master_sig',    default_val='', err_msg="Missing master signature from body",    err=err)
    rotating_sig:  str = base.dict_require(d=get.json, key='rotating_sig',  default_val='', err_msg="Missing rotating signature from body",  err=err)
    if len(err.msg_list):
        return html_bad_response(400, err.msg_list)

    # Parse and validate values
    if version != 0:
        err.msg_list.append(f'Unrecognised version passed: {version}')
    master_pkey_bytes   = base.hex_to_bytes(hex=master_pkey,   label='Master public key',      hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2, err=err)
    rotating_pkey_bytes = base.hex_to_bytes(hex=rotating_pkey, label='Rotating public key',    hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2, err=err)
    master_sig_bytes    = base.hex_to_bytes(hex=master_sig,    label='Master key signature',   hex_len=nacl.bindings.crypto_sign_BYTES * 2,          err=err)
    rotating_sig_bytes  = base.hex_to_bytes(hex=rotating_sig,  label='Rotating key signature', hex_len=nacl.bindings.crypto_sign_BYTES * 2,          err=err)
    if len(err.msg_list):
        return html_bad_response(400, err.msg_list)

    # Request proof from the backend
    with open_db_from_flask_request_context(flask.current_app) as db:
        proof = backend.get_pro_subscription_proof(sql_conn       = db.sql_conn,
                                                   version        = version,
                                                   signing_key    = db.runtime.backend_key,
                                                   gen_index_salt = db.runtime.gen_index_salt,
                                                   master_pkey    = nacl.signing.VerifyKey(master_pkey_bytes),
                                                   rotating_pkey  = nacl.signing.VerifyKey(rotating_pkey_bytes),
                                                   unix_ts_s      = unix_ts_s,
                                                   master_sig     = master_sig_bytes,
                                                   rotating_sig   = rotating_sig_bytes,
                                                   err            = err)

    result = html_bad_response(400, err.msg_list) if len(err.msg_list) else html_good_response(proof.to_dict())
    return result

@flask_blueprint.route(ROUTE_GET_REVOCATIONS, methods=['POST'])
def get_revocations():
    # Get JSON from request
    get: GetJSONFromFlaskRequest = get_json_from_flask_request(flask.request)
    if len(get.err_msg):
        return html_bad_response(400, get.err_msg)

    # Extract values from JSON
    err          = base.ErrorSink()
    version: int = base.dict_require(d=get.json, key='version', default_val=0, err_msg="Missing version from body",          err=err)
    ticket:  int = base.dict_require(d=get.json, key='ticket',  default_val=0, err_msg="Missing revocation ticket from body", err=err)
    if len(err.msg_list):
        return html_bad_response(400, err.msg_list)

    # Parse and validate values
    if version != 0:
        err.msg_list.append(f'Unrecognised version passed: {version}')
    if len(err.msg_list):
        return html_bad_response(400, err.msg_list)

    revocation_list:   list[dict[str, str | int]] = []
    revocation_ticket: int = 0
    with open_db_from_flask_request_context(flask.current_app) as db:
        revocation_ticket = backend.get_revocation_ticket(db.sql_conn)
        if ticket < revocation_ticket:
            with base.SQLTransaction(db.sql_conn) as tx:
                list_it: collections.abc.Iterator[tuple[int, int]] = backend.get_revocations_item_list_iterator(tx)
                for row in list_it:
                    gen_index:        int = row[0]
                    expiry_unix_ts_s: int = row[1]
                    gen_index_hash: bytes = backend.make_gen_index_hash(gen_index=gen_index, gen_index_salt=db.runtime.gen_index_salt)
                    assert gen_index < db.runtime.gen_index
                    assert len(db.runtime.gen_index_salt) == hashlib.blake2b.SALT_SIZE
                    revocation_list.append({
                        'expiry_unix_ts_s': expiry_unix_ts_s,
                        'gen_index_hash':   gen_index_hash.hex(),
                    })

    result = html_good_response({'version': 0, 'ticket': revocation_ticket, 'list': revocation_list})
    return result

@flask_blueprint.route(ROUTE_GET_PAYMENTS, methods=['POST'])
def get_payments():
    # Get JSON from request
    get: GetJSONFromFlaskRequest = get_json_from_flask_request(flask.request)
    if len(get.err_msg):
        return html_bad_response(400, get.err_msg)

    # Extract values from JSON
    err              = base.ErrorSink()
    version:     int = base.dict_require(d=get.json, key='version',     default_val=0,  err_msg="Missing version from body",           err=err)
    master_pkey: str = base.dict_require(d=get.json, key='master_pkey', default_val='', err_msg="Missing master public key from body", err=err)
    master_sig:  str = base.dict_require(d=get.json, key='master_sig',  default_val='', err_msg="Missing master signature from body",  err=err)
    timestamp:   int = base.dict_require(d=get.json, key='timestamp',   default_val=0,  err_msg="Missing timestamp from body",         err=err)
    page:        int = base.dict_require(d=get.json, key='page',        default_val=0,  err_msg="Missing page from body",              err=err)
    if len(err.msg_list):
        return html_bad_response(400, err.msg_list)

    # Parse and validate values
    if version != 0:
        err.msg_list.append(f'Unrecognised version passed: {version}')
    master_pkey_bytes = base.hex_to_bytes(hex=master_pkey,   label='Master public key',      hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2, err=err)
    master_sig_bytes  = base.hex_to_bytes(hex=master_sig,    label='Master key signature',   hex_len=nacl.bindings.crypto_sign_BYTES * 2,          err=err)

    # Validate timestamp
    # TODO: We _could_ track the last GET_ALL_PAYMENTS_MAX_TIMESTAMP_DELTA_S seconds worth of
    # requests to completely reject replay attacks if we cared enough but onion requests probably
    # suffice to mask the ability to replay a query.
    timestamp_delta: float = time.time() - float(timestamp)
    if abs(timestamp_delta) >= GET_ALL_PAYMENTS_MAX_TIMESTAMP_DELTA_S:
        err.msg_list.append(f'Timestamp is too old to permit retrieval of payments, delta was {timestamp_delta}s')

    if len(err.msg_list):
        return html_bad_response(400, err.msg_list)

    # Validate the signature
    master_pkey_nacl      = nacl.signing.VerifyKey(master_pkey_bytes)
    hash_to_verify: bytes = make_get_all_payments_hash(version=version, master_pkey=master_pkey_nacl, timestamp=timestamp, page=page)
    try:
        _ = master_pkey_nacl.verify(smessage=hash_to_verify, signature=master_sig_bytes)
    except Exception as e:
        err.msg_list.append('Signature failed to be verified')
        return html_bad_response(400, err.msg_list)

    total_payments: int                        = 0
    total_pages:    int                        = 0
    item_list:      list[dict[str, str | int]] = []
    with open_db_from_flask_request_context(flask.current_app) as db:
        total_payments = backend.get_all_payments_for_master_pkey_count(db.sql_conn, master_pkey=master_pkey_nacl)
        total_pages    = math.ceil(total_payments / backend.ALL_PAYMENTS_PAGINATION_SIZE)
        offset         = page * backend.ALL_PAYMENTS_PAGINATION_SIZE
        with base.SQLTransaction(db.sql_conn) as tx:
            list_it: collections.abc.Iterator[tuple[int, int, int, bytes, int]] = \
                    backend.get_all_payments_for_master_pkey_iterator(tx=tx, master_pkey=master_pkey_nacl, offset=offset)
            for row in list_it:
                subscription_duration_s: int   = row[0]
                creation_unix_ts_s:      int   = row[1]
                activation_unix_ts_s:    int   = row[2]
                payment_token_hash:      bytes = row[3]
                archive_unix_ts_s:       int   = row[4]

                item_list.append({
                    'subscription_duration_s': subscription_duration_s,
                    'creation_unix_ts_s':      creation_unix_ts_s,
                    'activation_unix_ts_s':    activation_unix_ts_s,
                    'payment_token_hash':      payment_token_hash.hex(),
                    'archive_unix_ts_s':       archive_unix_ts_s,
                })

    result = html_good_response({'version': 0, 'pages': total_pages, 'payments': total_payments, 'list': item_list})
    return result
