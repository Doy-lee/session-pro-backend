import flask
import typing
import time

flask_app: flask.Flask = flask.Flask(__name__)

class ErrorSink:
    msg_list: list[str] = []
    def __init__(self):
        self.msg_list.clear()

def dict_require(d: dict[str, typing.Any], key: str, default_val: typing.Any, err_msg: str, err: ErrorSink) -> typing.Any:
    if not key in d:
        err.msg_list.append(f'{err_msg}: \'{key}\'')
    return d.get(key, default_val)

def hex_to_bytes(hex: str, label: str, hex_len: int, err: ErrorSink) -> bytes:
    result: bytes = b''
    if len(hex) != hex_len:
        err.msg_list.append(f'{label} was not {hex_len} characters, was {len(hex)} characters')
    else:
        try:
            result = bytes.fromhex(hex)
        except Exception as e:
            err.msg_list.append(f'{label} was not valid hex: {e}')
    return result


def html_error_response(http_status: int, msg: str | list[str]) -> flask.Response:
    result = flask.jsonify({ 'status': http_status, 'msg': msg})
    return result

@flask_app.route('/add_payment', methods=['POST'])
def add_payment():
    if len(flask.request.get_data()) == 0:
        return html_error_response(400, "No JSON was present in body")

    # Get JSON from body
    json: dict[str, typing.Any] | None = None
    try:
        json = flask.request.get_json()
    except Exception as e:
        return html_error_response(400, f"{e}")

    if json is None:
        return html_error_response(400, "JSON failed to be parsed")

    # Extract values from JSON
    err:           ErrorSink = ErrorSink()
    version:       int       = dict_require(d=json, key='version',       default_val=0,  err_msg="Missing version from body",             err=err)
    master_pkey:   str       = dict_require(d=json, key='master_pkey',   default_val='', err_msg="Missing master public key from body",   err=err)
    rotating_pkey: str       = dict_require(d=json, key='rotating_pkey', default_val='', err_msg="Missing rotating public key from body", err=err)
    payment_token: str       = dict_require(d=json, key='payment_token', default_val='', err_msg="Missing payment token from body",       err=err)
    master_sig:    str       = dict_require(d=json, key='master_sig',    default_val='', err_msg="Missing master signature from body",    err=err)
    rotating_sig:  str       = dict_require(d=json, key='rotating_sig',  default_val='', err_msg="Missing rotating signature from body",  err=err)
    if len(err.msg_list):
        return html_error_response(400, err.msg_list)

    # Parse and validate values
    if version != 0:
        err.msg_list.append(f'Unrecognised version passed: {version}')
    master_pkey_bytes   = hex_to_bytes(hex=master_pkey,   label='Master public key',      hex_len=64, err=err)
    rotating_pkey_bytes = hex_to_bytes(hex=rotating_pkey, label='Rotating public key',    hex_len=64, err=err)
    payment_token_bytes = hex_to_bytes(hex=payment_token, label='Payment token',          hex_len=64, err=err)
    master_sig_bytes    = hex_to_bytes(hex=master_sig,    label='Master key signature',   hex_len=128, err=err)
    rotating_sig_bytes  = hex_to_bytes(hex=rotating_sig,  label='Rotating key signature', hex_len=128, err=err)
    if len(err.msg_list):
        return html_error_response(400, err.msg_list)

    return html_error_response(200, "good")

@flask_app.route('/get_pro_subscription_proof', methods=['POST'])
def get_pro_subscription_proof():
    if len(flask.request.get_data()) == 0:
        return html_error_response(400, "No JSON was present in body")

    # Get JSON from body
    json: dict[str, typing.Any] | None = None
    try:
        json = flask.request.get_json()
    except Exception as e:
        return html_error_response(400, f"{e}")

    if json is None:
        return html_error_response(400, "JSON failed to be parsed")

    # Extract values from JSON
    err:           ErrorSink = ErrorSink()
    version:       int       = dict_require(d=json, key='version',       default_val=0,  err_msg="Missing version from body",             err=err)
    master_pkey:   str       = dict_require(d=json, key='master_pkey',   default_val='', err_msg="Missing master public key from body",   err=err)
    rotating_pkey: str       = dict_require(d=json, key='rotating_pkey', default_val='', err_msg="Missing rotating public key from body", err=err)
    unix_ts_s:     int       = dict_require(d=json, key='unix_ts_s',     default_val=0,  err_msg="Missing unix timestamp from body",      err=err)
    master_sig:    str       = dict_require(d=json, key='master_sig',    default_val='', err_msg="Missing master signature from body",    err=err)
    rotating_sig:  str       = dict_require(d=json, key='rotating_sig',  default_val='', err_msg="Missing rotating signature from body",  err=err)
    if len(err.msg_list):
        return html_error_response(400, err.msg_list)

    # Parse and validate values
    if version != 0:
        err.msg_list.append(f'Unrecognised version passed: {version}')

    master_pkey_bytes   = hex_to_bytes(hex=master_pkey,   label='Master public key',      hex_len=64, err=err)
    rotating_pkey_bytes = hex_to_bytes(hex=rotating_pkey, label='Rotating public key',    hex_len=64, err=err)

    NONCE_THRESHOLD_S: int = 60 * 10; # 10 minutes
    now:               int = int(time.time())
    max_unix_ts_s:     int = now + NONCE_THRESHOLD_S
    min_unix_ts_s:     int = now - NONCE_THRESHOLD_S

    if unix_ts_s < min_unix_ts_s:
        err.msg_list.append(f'Nonce timestamp is too far in the past: {unix_ts_s} (min {min_unix_ts_s})')
    if unix_ts_s > max_unix_ts_s:
        err.msg_list.append(f'Nonce timestamp is too far in the future: {unix_ts_s} (max {max_unix_ts_s})')

    master_sig_bytes    = hex_to_bytes(hex=master_sig,    label='Master key signature',   hex_len=128, err=err)
    rotating_sig_bytes  = hex_to_bytes(hex=rotating_sig,  label='Rotating key signature', hex_len=128, err=err)
    if len(err.msg_list):
        return html_error_response(400, err.msg_list)

    return html_error_response(200, "good")
