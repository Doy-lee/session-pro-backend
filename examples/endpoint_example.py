import hashlib
import urllib.request
import nacl.signing
import os
import json
import time
import argparse

# NOTE: Setup variables
request_version                     = 0
get_pro_proof_example               = True
get_pro_status_example              = True
add_pro_payment_example             = True
add_pro_payment_example_with_google = True
add_pro_payment_example_with_apple  = True
get_revocations_list_example        = True

# NOTE: CLI handler
parser = argparse.ArgumentParser()
parser.add_argument( '-u', '--url', type=str, required=True, help='URL to the server to run the example on')
args = parser.parse_args()

# NOTE: Start executing example
master_key   = nacl.signing.SigningKey.generate()
rotating_key = nacl.signing.SigningKey.generate()
print('Master SKey: ' + bytes(master_key).hex())
print('Master PKey: ' + bytes(master_key.verify_key).hex())
print('Rotating SKey: ' + bytes(rotating_key).hex())
print('Rotating PKey: ' + bytes(rotating_key.verify_key).hex())

if add_pro_payment_example: # Register a fake payment on google and apple respectively
    if add_pro_payment_example_with_google:
        google_enum               = 1                    # equivalent to => int(base.PaymentProvider.GooglePlayStore.value)
        google_payment_token: str = os.urandom(16).hex() # For the payment token, anything is accepted on a development server
        google_order_id:      str = os.urandom(16).hex() # For the order ID, anything is accepted on a development server

        hasher: hashlib.blake2b = hashlib.blake2b(digest_size=32, person=b'SeshProBackend__')
        hasher.update(request_version.to_bytes(length=1, byteorder='little'))
        hasher.update(bytes(master_key.verify_key))
        hasher.update(bytes(rotating_key.verify_key))
        hasher.update(int(google_enum).to_bytes(length=1, byteorder='little'))
        hasher.update(google_payment_token.encode('utf-8'))
        hasher.update(google_order_id.encode('utf-8'))

        request_body={
            'version':       request_version,
            'master_pkey':   bytes(master_key.verify_key).hex(),
            'rotating_pkey': bytes(rotating_key.verify_key).hex(),
            'master_sig':    bytes(master_key.sign(hasher.digest()).signature).hex(),
            'rotating_sig':  bytes(rotating_key.sign(hasher.digest()).signature).hex(),
            'payment_tx': { 'provider': google_enum, 'google_payment_token': google_payment_token, 'google_order_id': google_order_id }
        }

        print('\n--\n')
        print('Add Pro Payment via Google')
        print('Request:\n' + json.dumps(request_body, indent=1))

        request = urllib.request.Request(f'{args.url}/add_pro_payment', data=json.dumps(request_body).encode('utf-8'), headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request) as response:
            response_data = json.loads(response.read().decode('utf-8'))
            print(f"Response: {json.dumps(response_data, indent=1)}")

    if add_pro_payment_example_with_apple: # apple
        apple_enum       = 2                    # equivalent to => int(base.PaymentProvider.iOSAppStore.value)
        apple_tx_id: str = os.urandom(16).hex() # For the tx id, anything is accepted on a development server

        hasher: hashlib.blake2b = hashlib.blake2b(digest_size=32, person=b'SeshProBackend__')
        hasher.update(request_version.to_bytes(length=1, byteorder='little'))
        hasher.update(bytes(master_key.verify_key))
        hasher.update(bytes(rotating_key.verify_key))
        hasher.update(int(apple_enum).to_bytes(length=1, byteorder='little'))
        hasher.update(apple_tx_id.encode('utf-8'))

        request_body={
            'version':       request_version,
            'master_pkey':   bytes(master_key.verify_key).hex(),
            'rotating_pkey': bytes(rotating_key.verify_key).hex(),
            'master_sig':    bytes(master_key.sign(hasher.digest()).signature).hex(),
            'rotating_sig':  bytes(rotating_key.sign(hasher.digest()).signature).hex(),
            'payment_tx': { 'provider': apple_enum, 'apple_tx_id': apple_tx_id, }
        }

        print('\n--\n')
        print('Add Pro Payment via Apple')
        print('Request:\n' + json.dumps(request_body, indent=1))

        request = urllib.request.Request(f'{args.url}/add_pro_payment', data=json.dumps(request_body).encode('utf-8'), headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request) as response:
            response_data = json.loads(response.read().decode('utf-8'))
            print(f"Response: {json.dumps(response_data, indent=1)}")

if get_pro_proof_example:
    version         = 0
    unix_ts_ms      = int(time.time() * 1000)

    hasher: hashlib.blake2b = hashlib.blake2b(digest_size=32, person=b'SeshProBackend__')
    hasher.update(version.to_bytes(length=1, byteorder='little'))
    hasher.update(bytes(master_key.verify_key))
    hasher.update(bytes(rotating_key.verify_key))
    hasher.update(unix_ts_ms.to_bytes(length=8, byteorder='little'))
    hash_to_sign: bytes = hasher.digest()

    request_body = {
        'version':       version,
        'master_pkey':   bytes(master_key.verify_key).hex(),
        'rotating_pkey': bytes(rotating_key.verify_key).hex(),
        'unix_ts_ms':     unix_ts_ms,
        'master_sig':    bytes(master_key.sign(hash_to_sign).signature).hex(),
        'rotating_sig':  bytes(rotating_key.sign(hash_to_sign).signature).hex(),
    }

    print('\n--\n')
    print('Get Pro Proof')
    print('Request:\n' + json.dumps(request_body, indent=1))

    request = urllib.request.Request(f'{args.url}/get_pro_proof', data=json.dumps(request_body).encode('utf-8'), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request) as response:
        response_data = json.loads(response.read().decode('utf-8'))
        print(f"Response: {json.dumps(response_data, indent=1)}")


if get_pro_status_example:
    version:    int = 0
    unix_ts_ms: int = int(time.time() * 1000)
    count:      int = 2

    hasher: hashlib.blake2b = hashlib.blake2b(digest_size=32, person=b'SeshProBackend__')
    hasher.update(version.to_bytes(length=1, byteorder='little'))
    hasher.update(bytes(master_key.verify_key))
    hasher.update(unix_ts_ms.to_bytes(length=8, byteorder='little'))
    hasher.update(count.to_bytes(length=4, byteorder='little'))
    hash_to_sign: bytes = hasher.digest()

    request_body = {'version':     version,
                    'master_pkey': bytes(master_key.verify_key).hex(),
                    'master_sig':  bytes(master_key.sign(hash_to_sign).signature).hex(),
                    'unix_ts_ms':  unix_ts_ms,
                    'count':       count}

    print('\n--\n')
    print('Get Pro Status')
    print('Request:\n' + json.dumps(request_body, indent=1))

    request = urllib.request.Request(f'{args.url}/get_pro_status', data=json.dumps(request_body).encode('utf-8'), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request) as response:
        response_data = json.loads(response.read().decode('utf-8'))
        print(f"Response: {json.dumps(response_data, indent=1)}")


if get_revocations_list_example:
    request_body = {'version': 0, 'ticket': 0 }

    print('\n--\n')
    print('Get Revocation List')
    print('Request:\n' + json.dumps(request_body, indent=1))

    request = urllib.request.Request(f'{args.url}/get_pro_revocations', data=json.dumps(request_body).encode('utf-8'), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request) as response:
        response_data = json.loads(response.read().decode('utf-8'))
        print(f"Response: {json.dumps(response_data, indent=1)}")


