import hashlib
import urllib.request
import nacl.signing
import os
import json

request_version = 0
if 1: # google
    master_key                = nacl.signing.SigningKey.generate()
    rotating_key              = nacl.signing.SigningKey.generate()
    google_enum               = 1                    # equivalent to => int(base.PaymentProvider.GooglePlayStore.value)
    google_payment_token: str = os.urandom(32).hex() # For the payment token, we accept anything right now, no verification is done

    hasher: hashlib.blake2b = hashlib.blake2b(digest_size=32, person=b'SeshProBackend__')
    hasher.update(request_version.to_bytes(length=1, byteorder='little'))
    hasher.update(bytes(master_key.verify_key))
    hasher.update(bytes(rotating_key.verify_key))
    hasher.update(int(google_enum).to_bytes(length=1, byteorder='little'))
    hasher.update(google_payment_token.encode('utf-8'))

    request_body={
        'version':       request_version,
        'master_pkey':   bytes(master_key.verify_key).hex(),
        'rotating_pkey': bytes(rotating_key.verify_key).hex(),
        'master_sig':    bytes(master_key.sign(hasher.digest()).signature).hex(),
        'rotating_sig':  bytes(rotating_key.sign(hasher.digest()).signature).hex(),
        'payment_tx': { 'provider': google_enum, 'google_payment_token': google_payment_token }
    }

    request = urllib.request.Request("https://session-pro-backend-dev.doylet.dev/add_pro_payment", data=json.dumps(request_body).encode('utf-8'), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request) as response:
        response_data = json.loads(response.read().decode('utf-8'))
        print(f"GOOGLE Response: {json.dumps(response_data, indent=1)}")

if 1: # apple
    master_key       = nacl.signing.SigningKey.generate()
    rotating_key     = nacl.signing.SigningKey.generate()
    apple_enum       = 2                    # equivalent to => int(base.PaymentProvider.iOSAppStore.value)
    apple_tx_id: str = os.urandom(32).hex() # For the tx id, we accept anything right now, no verification is done

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

    request = urllib.request.Request("https://session-pro-backend-dev.doylet.dev/add_pro_payment", data=json.dumps(request_body).encode('utf-8'), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request) as response:
        response_data = json.loads(response.read().decode('utf-8'))
        print(f"APPLE Response: {json.dumps(response_data, indent=1)}")
