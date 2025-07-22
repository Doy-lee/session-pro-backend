import nacl.signing
import os
import time
import json

import base
import backend

def do_test():
    db_setup:           backend.SetupDBResult   = backend.setup_db(':memory:')
    backend_key:        nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    master_key:         nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    rotating_key:       nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    creation_unix_ts_s: int                     = base.round_unix_ts_to_next_day(int(time.time()))

    print(f'Session Pro Test Suite\n{backend.db_header_string(db_setup)}')
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
        backend.add_unredeemed_payment(sql_conn=db_setup.sql_conn,
                                       payment_token_hash=it.payment_token_hash,
                                       subscription_duration_s=it.subscription_duration_s)

        unredeemed_payment_list: list[backend.UnredeemedPaymentRow] = backend.get_unredeemed_payments_list(db_setup.sql_conn)
        assert len(unredeemed_payment_list)                == 1
        unredeemed_payment_list[0].payment_token_hash      == it.payment_token_hash
        unredeemed_payment_list[0].subscription_duration_s == it.subscription_duration_s

        # Register the payment
        add_payment_hash: bytes = backend.make_add_payment_hash(master_pkey=master_key.verify_key,
                                                                rotating_key=rotating_key.verify_key,
                                                                payment_token_hash=it.payment_token_hash)

        it.proof = backend.add_payment(sql_conn           = db_setup.sql_conn,
                                       signing_key        = backend_key,
                                       creation_unix_ts_s = creation_unix_ts_s,
                                       master_pkey        = master_key.verify_key,
                                       rotating_pkey      = rotating_key.verify_key,
                                       payment_token_hash = it.payment_token_hash,
                                       master_sig         = master_key.sign(add_payment_hash),
                                       rotating_sig       = rotating_key.sign(add_payment_hash))
        print("Generated proof: {}".format(json.dumps(it.proof.to_dict(), indent=2)))
        assert it.proof.success

        # Verify payment was redeemed
        unredeemed_payment_list = backend.get_unredeemed_payments_list(db_setup.sql_conn)
        assert len(unredeemed_payment_list) == 0

    runtime: backend.RuntimeRow                     = backend.get_runtime(db_setup.sql_conn)
    assert runtime.gen_index                       == 2

    user_list: list[backend.UserRow]                = backend.get_users_list(db_setup.sql_conn)
    assert len(user_list)                          == 1
    assert user_list[0].master_pkey                == bytes(master_key.verify_key), "lhs={}, rhs={}".format(user_list[0].master_pkey.hex(), bytes(master_key.verify_key).hex())
    assert user_list[0].gen_index                  == runtime.gen_index - 1
    assert user_list[0].expiry_unix_ts             == creation_unix_ts_s + scenarios[0].subscription_duration_s + scenarios[1].subscription_duration_s + base.SECONDS_IN_DAY

    payment_list: list[backend.PaymentRow]          = backend.get_payments_list(db_setup.sql_conn)
    assert len(payment_list)                       == 2
    assert payment_list[0].master_pkey             == bytes(master_key.verify_key), "lhs={}, rhs={}".format(payment_list[0].master_pkey.hex(), bytes(master_key.verify_key).hex())
    assert payment_list[0].subscription_duration_s == scenarios[0].subscription_duration_s
    assert payment_list[0].creation_unix_ts_s      == creation_unix_ts_s
    assert payment_list[0].activation_unix_ts_s    == creation_unix_ts_s
    assert payment_list[0].payment_token_hash      == scenarios[0].payment_token_hash

    assert payment_list[1].master_pkey             == bytes(master_key.verify_key), "lhs={}, rhs={}".format(payment_list[0].master_pkey.hex(), bytes(master_key.verify_key).hex())
    assert payment_list[1].subscription_duration_s == scenarios[1].subscription_duration_s
    assert payment_list[1].creation_unix_ts_s      == creation_unix_ts_s
    assert payment_list[1].activation_unix_ts_s    == None
    assert payment_list[1].payment_token_hash      == scenarios[1].payment_token_hash

    revocation_list: list[backend.RevocationRow]    = backend.get_revocations_list(db_setup.sql_conn)
    assert len(revocation_list)                    == 1
    assert revocation_list[0].gen_index            == 0
    assert revocation_list[0].expiry_unix_ts       == creation_unix_ts_s + scenarios[0].subscription_duration_s + base.SECONDS_IN_DAY

    base.print_db_to_stdout(db_setup.sql_conn)

