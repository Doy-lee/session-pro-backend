'''A shim that can be plugged into a Flask server enabling onion requests
routes. An onion request is a request that is encrypted for the server's X25519
public key that is then unwrapped and forwarded to the desired endpoint defined
in the encrypted payload.

A flask application can integrate onion requests in 2 steps. First enable the
routes by registering the blueprint to your application, then, create
a long-term X25519 key for the server and then make it available to a Flask
request by storing it in the Flask configuration dictionary so that the server
can decrypt incoming client requests that are encrypted.

1. Enable the desired routes on your Flask application. We currently have v3 and
v4 routes (v3 is provided for legacy reasons, use v4 if you're starting a new
application)

    import onion_req
    flask_app = flask.Flask(__name__)
    flask_app.register_blueprint(onion_req.flask_blueprint_v3)
    flask_app.register_blueprint(onion_req.flask_blueprint_v4)

2. Set the long-term X25519 key on the Flask dictionary

    import nacl.public
    x25519_skey                                                    = nacl.public.PrivateKey.generate()
    flask_app.config[onion_req.FLASK_CONFIG_ONION_REQ_X25519_SKEY] = x25519_skey

The integration application will now respond to onion requests on the following
v3 and v4 routes respectively:

    /loki/v3/lsrpc
    /oxen/v3/lsrpc
    /oxen/v4/lsrpc

Upon sending a request, the encrypted request is decrypted by the X25519 secret
key, the payload is parsed and the desired endpoint and endpoint arguments are
extracted. The onion request layer will then internally route the request to the
Flask server with the extracted data, get the response and return it to the
client.

See the doc comments for the individual routes below for more details on the
required composition of the onion request payload. For details on the underlying
request, see:

    https://github.com/session-foundation/libsession-util/blob/551a48b258f53a36c4cd1ad036d65e3dcd575fbc/src/onionreq/parser.cpp

Additionally in this file there are helper functions to construct a onion
request and functions to decode an onion response. A rough self-contained
example is available at `test_onion_request_response_lifecycle`
'''

import json
import nacl.bindings
import nacl.public
import nacl.secret
import hashlib
import traceback

from flask import request, abort, current_app, Blueprint
from io import BytesIO
from typing import Optional, Union, Any, Tuple

from session_util.onionreq import OnionReqParser

class Response:
    success:  bool           = False
    metadata: dict[str, Any] = {}
    body:     bytes          = b''

FLASK_CONFIG_ONION_REQ_X25519_SKEY = 'onion_req_x25519_skey'
ROUTE_OXEN_V3_LSRPC                = '/oxen/v3/lsrpc'
ROUTE_LOKI_V3_LSRPC                = '/loki/v3/lsrpc'
ROUTE_OXEN_V4_LSRPC                = '/oxen/v4/lsrpc'
HTTP_BODY_METHODS                  = ('POST', 'PUT')
HTTP_BAD_REQUEST                   = 400
HTTP_OK                            = 200
flask_blueprint_v3                 = Blueprint('onion-req-blueprint-v3', __name__)
flask_blueprint_v4                 = Blueprint('onion-req-blueprint-v4', __name__)

def make_shared_key(our_x25519_skey: nacl.public.PrivateKey,
                    server_x25519_pkey: nacl.public.PublicKey) -> bytes:
    # NOTE: Construct the shared key as follows:
    #
    #   > xchacha20-poly1305 encryption; for a message sent from client Alice to server Bob we use a
    #   > shared key of a Blake2B 32-byte (i.e. crypto_aead_xchacha20poly1305_ietf_KEYBYTES) hash of
    #   > H(aB || A || B), which Bob can compute when receiving as H(bA || A || B).  The returned value
    #   > always has the crypto_aead_xchacha20poly1305_ietf_NPUBBYTES nonce prepended to the beginning.
    #
    #   > When Bob (the server) encrypts a method for Alice (the client), he uses shared key
    #   > H(bA || A || B) (note that this is *different* that what would result if Bob was a client
    #   > sending to Alice the client).
    #
    # References:
    #   https://github.com/session-foundation/libsession-util/blob/551a48b258f53a36c4cd1ad036d65e3dcd575fbc/include/session/onionreq/hop_encryption.hpp
    #   https://github.com/session-foundation/libsession-util/blob/551a48b258f53a36c4cd1ad036d65e3dcd575fbc/src/onionreq/hop_encryption.cpp#L58

    # Construct aB
    aB_key: bytes = nacl.bindings.crypto_scalarmult(bytes(our_x25519_skey), bytes(server_x25519_pkey))

    # Construct H(ab || A || B)
    hasher = hashlib.blake2b(digest_size=nacl.bindings.crypto_aead_chacha20poly1305_ietf_KEYBYTES)
    hasher.update(aB_key)
    hasher.update(bytes(our_x25519_skey.public_key))
    hasher.update(bytes(server_x25519_pkey))

    # Construct shared key
    result = hasher.digest()
    return result

def make_request_v4(our_x25519_pkey: nacl.public.PublicKey,
                    shared_key: bytes,
                    endpoint: str,
                    request_body: dict[str, Any]) -> bytes:

    assert len(shared_key) == nacl.bindings.crypto_aead_chacha20poly1305_ietf_KEYBYTES
    aead = nacl.secret.Aead(key=shared_key)

    # Construct the payloads to bencode that will be encrypted
    request_metadata = {
        'method': 'POST',
        'endpoint': endpoint,
        'headers': {
            'Content-Type': 'application/json'
        }
    }
    request_metadata_json_str = json.dumps(request_metadata, separators=(',', ':'))
    request_body_json_str     = json.dumps(request_body, separators=(',', ':'))

    # Construct the bencoded payload
    request_payload: bytes    = 'l{}:{}{}:{}e'.format(len(request_metadata_json_str),
                                                      request_metadata_json_str,
                                                      len(request_body_json_str),
                                                      request_body_json_str).encode('utf-8')

    # Construct encrypted payload
    encrypted_request_payload: bytes  = aead.encrypt(request_payload)

    onion_request_metadata = {
        'ephemeral_key': bytes(our_x25519_pkey).hex(),
        'enc_type': 'xchacha20-poly1305'
    }

    # Build the final payload to send off to the onion request endpoint
    #   <4 byte LE encrypted payload length><encrypted payload><onion request metadata>
    result: bytes = len(encrypted_request_payload).to_bytes(length=4, byteorder='little') + \
                        encrypted_request_payload + \
                        json.dumps(onion_request_metadata).encode('utf-8')
    return result

def make_response_v4(shared_key: bytes, encrypted_response: bytes) -> Response:
    result = Response()

    # Decrypt
    aead      = nacl.secret.Aead(key=shared_key)
    decrypted = aead.decrypt(encrypted_response)
    if not decrypted.startswith(b'l') or not decrypted.endswith(b'e'):
        return result

    # Decode
    trimmed_decrypted = memoryview(decrypted)[1:-1]
    metadata, body    = bencode_consume_string(trimmed_decrypted)

    # Finish
    result.success    = True
    result.metadata   = json.loads(metadata.tobytes())
    body_bytes: bytes = body.tobytes()
    if len(body_bytes) > 0:
        body_decoded, _ = bencode_consume_string(memoryview(body_bytes))
        result.body     = body_decoded.tobytes()
    return result

def encode_base64(data: bytes):
    return base64.b64encode(data).decode()

def bencode_consume_string(body: memoryview) -> Tuple[memoryview, memoryview]:
    """
    Parses a bencoded byte string from the beginning of `body`.  Returns a pair of memoryviews on
    success: the first is the string byte data; the second is the remaining data (i.e. after the
    consumed string).
    Raises ValueError on parse failure.
    """
    pos = 0
    while pos < len(body) and 0x30 <= body[pos] <= 0x39:  # 1+ digits
        pos += 1
    if pos == 0 or pos >= len(body) or body[pos] != 0x3A:  # 0x3a == ':'
        raise ValueError("Invalid string bencoding: did not find `N:` length prefix")

    strlen = int(body[0:pos])  # parse the digits as a base-10 integer
    pos += 1  # skip the colon
    if pos + strlen > len(body):
        raise ValueError("Invalid string bencoding: length exceeds buffer")
    return body[pos : pos + strlen], body[pos + strlen :]

def make_subrequest(
    method: str,
    path: str,
    *,
    headers={},
    content_type: Optional[str] = None,
    body: Optional[Union[bytes, memoryview]] = None,
    json: Optional[Union[dict, list]] = None,
):
    """
    Makes a subrequest from the given parameters, returns the response object and a dict of
    lower-case response headers keys to header values.

    Parameters:
    method - the HTTP method, e.g. GET or POST
    path - the request path (optionally including a query string)
    headers - dict of HTTP headers for the request
    content_type - the content-type of the request (for POST/PUT methods)
    body - the bytes content of the body of a POST/PUT method.  If specified then content_type will
    default to 'application/octet-stream'.
    json - a json value to dump as the body of the request.  If specified then content_type will
    default to 'applicaton/json'.
    """

    http_headers: dict[str, Any] = {'HTTP_{}'.format(h.upper().replace('-', '_')): v for h, v in headers.items()}

    if content_type is None:
        if 'HTTP_CONTENT_TYPE' in http_headers:
            content_type = http_headers['HTTP_CONTENT_TYPE']
        elif body is not None:
            content_type = 'application/octet-stream'
        elif json is not None:
            content_type = 'application/json'
        else:
            content_type = ''

    for x in ('HTTP_CONTENT_TYPE', 'HTTP_CONTENT_LENGTH'):
        if x in http_headers:
            del http_headers[x]

    if body is None:
        if json is not None:
            from json import dumps

            body = dumps(json, separators=(',', ':')).encode()
        else:
            body = b''

    body_input = BytesIO(body)
    content_length = len(body)

    if '?' in path:
        path, query_string = path.split('?', 1)
    else:
        query_string = ''

    # Set up the wsgi environ variables for the subrequest (see PEP 0333)
    subreq_env: dict[str, Any] = {
        **request.environ,
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query_string,
        "CONTENT_TYPE": content_type,
        # NOTE: Werkzeug as of v2.3.5 expects a string for content length otherwise
        # flask.request.get_data() will throw an exception due to trying to call string methods in
        # an attempt to parse the integer.
        #
        #   > When parsing numbers in HTTP request headers such as ``Content-Length``, only ASCII
        #   > digits are accepted rather than any format that Python's ``int`` and ``float`` accept.
        #
        # References:
        #   https://github.com/pallets/werkzeug/issues/2716
        #   https://github.com/pallets/werkzeug/pull/2723
        #
        "CONTENT_LENGTH": str(content_length),
        **http_headers,
        'wsgi.input': body_input,
        'flask._preserve_context': False,
    }

    try:
        current_app.logger.debug(f"Initiating sub-request for {method} {path}")
        with current_app.request_context(subreq_env):
            response = current_app.full_dispatch_request()
        if response.status_code != HTTP_OK:
            current_app.logger.warning(
                f"Sub-request for {method} {path} returned status {response.status_code}"
            )
        return response, {
            k.lower(): v
            for k, v in response.get_wsgi_headers(subreq_env)
            if k.lower() != 'content-length'
        }

    except Exception:
        current_app.logger.warning(f"Sub-request for {method} {path} failed: {traceback.format_exc()}")
        raise

def handle_v3_onionreq_plaintext(body):
    try:
        if not body.startswith(b'{'):
            raise RuntimeError("Invalid v3 onion request body: expected JSON object")

        req = json.loads(body)
        endpoint, method = req['endpoint'], req['method']
        subreq_headers = {k.lower(): v for k, v in req.get('headers', {}).items()}

        if method in HTTP_BODY_METHODS:
            subreq_body = req.get('body', '').encode()
        else:
            subreq_body = b''
            # Android bug workaround: Android Session (at least up to v1.11.12) sends a body on
            # GET requests with a 4-character string "null" when it should send no body.
            if 'body' in req and len(req['body']) == 4 and req['body'] == 'null':
                del req['body']

            if 'body' in req and req['body']:
                raise RuntimeError(
                    "Invalid {} {} request: request must not contain a body".format(
                        method, endpoint
                    )
                )

        if not endpoint.startswith('/'):
            endpoint = '/' + endpoint

        response, _headers = make_subrequest(
            method,
            endpoint,
            headers=subreq_headers,
            body=subreq_body,
            content_type='application/json',
        )

        if response.status_code == HTTP_OK:
            data = response.get_data()
            current_app.logger.debug(
                f"Onion sub-request for {endpoint} returned success, {len(data)} bytes"
            )
            return data
        return json.dumps({'status_code': response.status_code}).encode()

    except Exception as e:
        current_app.logger.warning("Invalid onion request: {}".format(e))
        return json.dumps({'status_code': HTTP_BAD_REQUEST}).encode()


def handle_v4_onionreq_plaintext(body):
    try:
        if not (body.startswith(b'l') and body.endswith(b'e')):
            raise RuntimeError("Invalid onion request body: expected bencoded list")

        belems = memoryview(body)[1:-1]

        # Metadata json; this element is always required:
        meta, belems = bencode_consume_string(belems)

        meta = json.loads(meta.tobytes())

        # Then we can have a second optional string containing the body:
        if len(belems) > 1:
            subreq_body, belems = bencode_consume_string(belems)
            if len(belems):
                raise RuntimeError("Invalid v4 onion request: found more than 2 parts")
        else:
            subreq_body = b''

        method, endpoint = meta['method'], meta['endpoint']
        if not endpoint.startswith('/'):
            raise RuntimeError("Invalid v4 onion request: endpoint must start with /")

        response, headers = make_subrequest(
            method, endpoint, headers=meta.get('headers', {}), body=subreq_body
        )

        data = response.get_data()
        current_app.logger.debug(
            f"Onion sub-request for {endpoint} returned {response.status_code}, {len(data)} bytes"
        )

        meta = {'code': response.status_code, 'headers': headers}

    except Exception as e:
        current_app.logger.warning("Invalid v4 onion request: {}".format(e))
        meta = {'code': HTTP_BAD_REQUEST, 'headers': {'content-type': 'text/plain; charset=utf-8'}}
        data = b'Invalid v4 onion request'

    meta = json.dumps(meta).encode()
    return b''.join(
        (b'l', str(len(meta)).encode(), b':', meta, str(len(data)).encode(), b':', data, b'e')
    )


def decrypt_onionreq():
    assert FLASK_CONFIG_ONION_REQ_X25519_SKEY in current_app.config
    assert isinstance(current_app.config.get(FLASK_CONFIG_ONION_REQ_X25519_SKEY), nacl.public.PrivateKey)
    x25519_skey = current_app.config[FLASK_CONFIG_ONION_REQ_X25519_SKEY]

    try:
        return OnionReqParser(
            x25519_pubkey=bytes(x25519_skey.public_key),
            x25519_privkey=bytes(x25519_skey),
            request=request.data)
    except Exception as e:
        current_app.logger.warning("Failed to decrypt onion request: {}".format(e))
    abort(HTTP_BAD_REQUEST)


@flask_blueprint_v3.post(ROUTE_OXEN_V3_LSRPC)
@flask_blueprint_v3.post(ROUTE_LOKI_V3_LSRPC)
def handle_onion_request():
    """
    Parse an onion request, handle it as a subrequest, then throw away the subrequest headers,
    replace the subrequest body with a json string, encrypt the final result and then pointlessly
    base64 encodes the body before sending it back to the requestor.

    Deprecated in favour of /v4/.

    This injects a subrequest to process it then returns the result of that subrequest (as bytes).

    The body must be JSON containing two always-required keys:

    - "endpoint" -- the HTTP endpoint to invoke (e.g. "/room/some-room").
    - "method" -- the HTTP method (e.g. "POST", "GET")

    Plus, when method is POST or PUT, the required field:

    - "body" -- the request body for POST/PUT requests

    Optional keys that may be included are:
    - "headers" -- optional dict of HTTP headers for the request.  Header names are
                   case-insensitive (i.e. `X-Foo` and `x-FoO` are equivalent).

    When returning, we invoke the subrequest and then, if it returns a 200 response code, we take
    the response body, encrypt it, and then base64 the encrypted body and send that back as the
    response body of the onion request.

    If the subrequest returned a non-200 response code then instead of the returned body we return
    `{"status_code":xxx}` (where xxx is the numeric status code) and encrypt/base64 encode that.

    Response headers are completely ignored, as are bodies of non-200 responses.

    This is deprecated because it amplifies request and response sizes, it doesn't allow non-json
    requests, and it drops pertinent request information (such as response headers and error
    bodies).  Prefer v4 requests which do not have these drawbacks.
    """

    parser = decrypt_onionreq()
    return encode_base64(parser.encrypt_reply(handle_v3_onionreq_plaintext(parser.payload)))

@flask_blueprint_v4.post(ROUTE_OXEN_V4_LSRPC)
def handle_v4_onion_request():
    """
    Handles a decrypted v4 onion request; this injects a subrequest to process it then returns the
    result of that subrequest.  In contrast to v3, it is more efficient (particularly for binary
    input or output) and allows using endpoints that return headers or bodies with non-2xx response
    codes.

    The body of a v4 request (post-decryption) is a bencoded list containing exactly 1 or 2 byte
    strings: the first byte string contains a json object containing the request metadata which has
    three required fields:

    - "endpoint" -- the HTTP endpoint to invoke (e.g. "/room/some-room").
    - "method" -- the HTTP method (e.g. "POST", "GET")
    - "headers" -- dict of HTTP headers for the request.  Header names are case-insensitive (i.e.
      `X-Foo` and `x-FoO` are equivalent).

    Unlike v3 requests, endpoints must always start with a /.  (If a legacy endpoint "whatever"
    needs to be accessed through a v4 request for some reason then it can be accessed via the
    "/legacy/whatever" endpoint).

    The "headers" field typically carries X-SOGS-* authentication headers as well as fields like
    Content-Type.  Note that, unlike v3 requests, the Content-Type does *not* have any default and
    should also be specified, often as `application/json`.  Unlike HTTP requests, Content-Length is
    not required and will be ignored if specified; the content-length is always determined from the
    provided body.

    The second byte string in the request, if present, is the request body in raw bytes and is
    required for POST and PUT requests and must not be provided for GET/DELETE requests.

    Bencoding details:
        A full bencode library can be used, but the format used here is deliberately meant to be as
        simple as possible to implement without a full bencode library on hand.  The format of a
        byte string is `N:` where N is a decimal number (e.g. `123:` starts a 123-byte string),
        followed by the N bytes.  A list of strings starts with `l`, contains any number of encoded
        byte strings, followed by `e`.  (Full bencode allows dicts, integers, and list/dict
        recursion, but we do not use any of that for v4 bencoded onion requests).

    For example, the request:

        GET /room/some-room
        Some-Header: 12345

    would be encoded as:

        l79:{"method":"GET","endpoint":"/room/some-room","headers":{"Some-Header":"12345"}}e

    that is: a list containing a single 79-byte string.  A POST request such as:

        POST /some/thing
        Some-Header: a

        post body here

    would be encoded as the two-string bencoded list:

        l72:{"method":"POST","endpoint":"/some/thing","headers":{"Some-Header":"a"}}14:post body heree
            ^^^^^^^^72-byte request info json^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^   ^^14-byte body^^

    The return value of the request is always a 2-part bencoded list where the first part contains
    response metadata and the second contains the response body.  The response metadata is a json
    object containing:
    - "code" -- the numeric HTTP response code (e.g. 200, 403); and
    - "headers" -- a json object of header names to values.  Note that, since HTTP headers are
      case-insensitive, the header names are always returned as lower-case, and we strip out the
      'content-length' header (since it is already encoded in the length of the body part).

    For example, a simple json request response might be the two parts:

    - `{"code":200,"headers":{"content-type":"application/json"}}`
    - `{"id": 123}`

    encoded as:

        l58:{"code":200,"headers":{"content-type":"application/json"}}11:{"id": 123}e

    A more complicated request, for example for a file download, might return binary content such as:

    - `{"code":200,"headers":{"content-type":"application/octet-stream","content-disposition":"attachment; filename*=UTF-8''filename.txt"}}`
    - `My file contents`

    i.e. encoded as `l132:{...the json above...}16:My file contentse`

    Error responses (e.g. a 403) are not treated specially; that is: they still have a "code" set to
    the response code and "headers" and a body part of whatever the request returned for a body).

    The final value returned from the endpoint is the encrypted bencoded bytes, and these encrypted
    bytes are returned directly to the client (i.e. no base64 encoding applied, unlike v3 requests).
    """  # noqa: E501

    # Some less-than-ideal decisions in the onion request protocol design means that we are stuck
    # dealing with parsing the request body here in the internal format that is meant for storage
    # server, but the *last* hop's decrypted, encoded data has to get shared by us (and is passed on
    # to us in its raw, encoded form).  It looks like this:
    #
    # [N][blob][json]
    #
    # where N is the size of blob (4 bytes, little endian), and json contains *both* the elements
    # that were meant for the last hop (like our host/port/protocol) *and* the elements that *we*
    # need to decrypt blob (specifically: "ephemeral_key" and, optionally, "enc_type" [which can be
    # used to use xchacha20-poly1305 encryption instead of AES-GCM]).
    #
    # The parse_junk here takes care of decoding and decrypting this according to the fields *meant
    # for us* in the json (which include things like the encryption type and ephemeral key):
    try:
        parser = decrypt_onionreq()
    except RuntimeError as e:
        current_app.logger.warning("Failed to decrypt onion request: {}".format(e))
        abort(HTTP_BAD_REQUEST)

    # On the way back out we re-encrypt via the junk parser (which uses the ephemeral key and
    # enc_type that were specified in the outer request).  We then return that encrypted binary
    # payload as-is back to the client which bounces its way through the SN path back to the client.
    response = handle_v4_onionreq_plaintext(parser.payload)
    return parser.encrypt_reply(response)

def test_onion_request_response_lifecycle():
    import flask
    import nacl.public
    import werkzeug

    # Build the shared key to encrypt for with our secret keys and the server's public key.
    server_x25519_skey = nacl.public.PrivateKey.generate()
    our_x25519_skey    = nacl.public.PrivateKey.generate()
    shared_key: bytes  = make_shared_key(our_x25519_skey=our_x25519_skey, server_x25519_pkey=server_x25519_skey.public_key)

    # Encrypt request for 'shared_key'
    onion_request: bytes = make_request_v4(our_x25519_pkey=our_x25519_skey.public_key,
                                           shared_key=shared_key,
                                           endpoint='/foo/post/endpoint',
                                           request_body={'bar':  5})

    # Setup a Flask server
    flask_app:    flask.Flask     = flask.Flask(__name__)
    flask_client: werkzeug.Client = flask_app.test_client()
    flask_app.register_blueprint(flask_blueprint_v4)                          # Add the v4 endpoints
    flask_app.config[FLASK_CONFIG_ONION_REQ_X25519_SKEY] = server_x25519_skey # Set the x25519 key

    # Register the endpoint
    @flask_app.post("/foo/post/endpoint")
    def foo_endpoint():
        return "Hello, World!"

    # Submit a v4 request, decrypt response and parse the returned body
    response:       werkzeug.test.TestResponse = flask_client.post(ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response: Response                   = make_response_v4(shared_key=shared_key, encrypted_response=response.data)

    # Parse the response
    assert onion_response.success
    assert onion_response.body == b'Hello, World!'
