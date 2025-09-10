import flask
import json
import typing
import base
import backend
import sqlite3
import sys

from appstoreserverlibrary.models.SendTestNotificationResponse  import SendTestNotificationResponse  as AppleSendTestNotificationResponse
from appstoreserverlibrary.models.CheckTestNotificationResponse import CheckTestNotificationResponse as AppleCheckTestNotificationResponse
from appstoreserverlibrary.models.Environment                   import Environment                   as AppleEnvironment
from appstoreserverlibrary.models.Type                          import Type                          as AppleType
from appstoreserverlibrary.models.TransactionReason             import TransactionReason             as AppleTransactionReason
from appstoreserverlibrary.models.JWSTransactionDecodedPayload  import JWSTransactionDecodedPayload  as AppleJWSTransactionDecodedPayload
from appstoreserverlibrary.models.Data                          import Data                          as AppleData
from appstoreserverlibrary.models.ResponseBodyV2DecodedPayload  import ResponseBodyV2DecodedPayload  as AppleResponseBodyV2DecodedPayload
from appstoreserverlibrary.models.Subtype                       import Subtype                       as AppleSubtype
from appstoreserverlibrary.models.NotificationTypeV2            import NotificationTypeV2            as AppleNotificationV2

from appstoreserverlibrary.api_client import (
    AppStoreServerAPIClient as AppleAppStoreServerAPIClient,
    APIException as AppleAPIException,
)

from appstoreserverlibrary.signed_data_verifier import (
    VerificationException        as AppleVerificationException,
    SignedDataVerifier           as AppleSignedDataVerifier,
)

# NOTE: Enforce the presence of platform_config.py and the variables required for Apple
# integration
try:
    import platform_config
    import_error = False
    if not hasattr(platform_config, 'apple_key_id') or not isinstance(platform_config.apple_key_id, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        print("ERROR: Missing 'apple_key_id' string in platform_config.py")
        import_error = True

    if not hasattr(platform_config, 'apple_issuer_id')  or not isinstance(platform_config.apple_issuer_id,  str):  # pyright: ignore[reportUnnecessaryIsInstance]
        print('ERROR: Missing \'apple_issuer_id\' string in platform_config.py')
        import_error = True

    if not hasattr(platform_config, 'apple_bundle_id')  or not isinstance(platform_config.apple_bundle_id,  str):  # pyright: ignore[reportUnnecessaryIsInstance]
        print('ERROR: Missing \'apple_bundle_id\' string in platform_config.py')
        import_error = True

    if not hasattr(platform_config, 'apple_key_bytes')  or not isinstance(platform_config.apple_key_bytes,  bytes):  # pyright: ignore[reportUnnecessaryIsInstance]
        print('ERROR: Missing \'apple_key_bytes\' bytes in platform_config.py')
        import_error = True

    if not hasattr(platform_config, 'apple_root_certs') or not isinstance(platform_config.apple_root_certs, list):  # pyright: ignore[reportUnnecessaryIsInstance]
        print('ERROR: Missing \'apple_root_certs\' list of bytes in platform_config.py')
        import_error = True

    if not all(isinstance(item, bytes) for item in platform_config.apple_root_certs): # pyright: ignore[reportUnnecessaryIsInstance]
        print('ERROR: Missing \'apple_root_certs\' list of bytes in platform_config.py')
        import_error = True

    if import_error:
        raise ImportError

except ImportError:
    print('''ERROR: 'platform_config.py' is not present or missing fields. Create and fill it e.g.:
  ```python
  import pathlib
  apple_key_id: str      = '<Private Key ID>'
  apple_issuer_id: str   = '<Key Issuer ID>'
  apple_bundle_id: str   = 'com.your_organisation.your_project'
  apple_key_bytes: bytes = pathlib.Path(f'<path/to/private_key>.p8').read_bytes()
  apple_root_certs: list[bytes] = [
      pathlib.Path(f'<path/to/AppleIncRootCertificate.cer>').read_bytes(),
      pathlib.Path(f'<path/to/AppleRootCA-G2.cer>').read_bytes(),
      pathlib.Path(f'<path/to/AppleRootCA-G3.cer>').read_bytes(),
  ]
  ```
''')
    sys.exit(1)


ROUTE_NOTIFICATIONS_APPLE_APP_CONNECT_SANDBOX = '/apple_notifications_v2'
flask_blueprint                               = flask.Blueprint('session-pro-backend-apple', __name__)

def require_field(field: typing.Any, msg: str, err: base.ErrorSink | None) -> bool:
    result = True
    if field is None:
        result = False
        if err:
            err.msg_list.append(msg)
    return result

@flask_blueprint.route(ROUTE_NOTIFICATIONS_APPLE_APP_CONNECT_SANDBOX, methods=['POST'])
def notifications_apple_app_connect_sandbox() -> flask.Response:
    print(f"Request: {flask.request.data}")
    flask.abort(500)

def test_apple_signed_payload():
    # Sample test notification payload from the testing endpoint
    payload = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTURDQ0E3YWdBd0lCQWdJUWZUbGZkMGZOdkZXdnpDMVlJQ' + \
              'U5zWGpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1' + \
              'YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWt' + \
              'HQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRY' + \
              'RFRJek1Ea3hNakU1TlRFMU0xb1hEVEkxTVRBeE1URTVOVEUxTWxvd2daSXhRREErQmdOVkJBTU1OMUJ5Y' + \
              'jJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSU' + \
              'ZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1' + \
              'Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJN' + \
              'R0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCRUZFWWUvSnFUcXlRdi9kdFhrYXVESENTY1YxMjlGW' + \
              'VJWLzB4aUIyNG5DUWt6UWYzYXNISk9OUjVyMFJBMGFMdko0MzJoeTFTWk1vdXZ5ZnBtMjZqWFNqZ2dJSU' + \
              '1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODV' + \
              'jK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNu' + \
              'UnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyT' + \
              'npjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRX' + \
              'dnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmx' + \
              'JRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpa' + \
              'WEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR' + \
              '0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0' + \
              'JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0l' + \
              'CRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3' + \
              'SFFZRFZSME9CQllFRkFNczhQanM2VmhXR1FsekUyWk9FK0dYNE9vL01BNEdBMVVkRHdFQi93UUVBd0lIZ' + \
              '0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3Tm9BREJsQWpFQTh5Uk5kc2twNT' + \
              'A2REZkUExnaExMSndBdjVKOGhCR0xhSThERXhkY1BYK2FCS2pqTzhlVW85S3BmcGNOWVVZNVlBakFQWG1' + \
              'NWEVaTCtRMDJhZHJtbXNoTnh6M05uS20rb3VRd1U3dkJUbjBMdmxNN3ZwczJZc2xWVGFtUllMNGFTczVr' + \
              'PSIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJe' + \
              'mowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMRE' + \
              'IxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3Ykd' + \
              'VZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURB' + \
              'd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKb' + \
              'GJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeE' + \
              'V6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0F' + \
              'RWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhK' + \
              'TUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjc' + \
              'HhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WU' + \
              'RWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTR' + \
              'NRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndj' + \
              'R3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaU' + \
              'zVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3Yk' + \
              'I4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2d' + \
              'xaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdk' + \
              'NkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V' + \
              '0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTk' + \
              'xGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN' + \
              '6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVH' + \
              'QTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV' + \
              '2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUn' + \
              'pNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVF' + \
              'ZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1' + \
              'QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqV' + \
              'HV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0' + \
              'lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl' + \
              '5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJB' + \
              'TURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnU' + \
              'FVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaG' + \
              'lkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJub3RpZmljYXRpb25UeXBlIjoiVEVTVCIsIm5vdGl' + \
              'maWNhdGlvblVVSUQiOiI1OTI3NTFlZi1jMWI4LTQ3ZmMtOTI5ZS1kNjJkZWU2NmRmNGMiLCJkYXRhIjp7' + \
              'ImJ1bmRsZUlkIjoiY29tLmxva2ktcHJvamVjdC5sb2tpLW1lc3NlbmdlciIsImVudmlyb25tZW50IjoiU' + \
              '2FuZGJveCJ9LCJ2ZXJzaW9uIjoiMi4wIiwic2lnbmVkRGF0ZSI6MTc1NzAzNTQ3MjY4Nn0.n9l9_ZitkG' + \
              's2x0-ByhW9fgGWFLgLpSanCEwkzbX2B4C92s5bV-rhB0JtxBLmmyAlUnH7jhVILoGalp-Xnz_qRg'

def entry_point():
    app_apple_id: int | None = None
    apple_env                = AppleEnvironment.SANDBOX
    if apple_env != AppleEnvironment.SANDBOX:
        assert app_apple_id is not None, "App ID must be set in a non-sandbox environment"

    apple_client = AppleAppStoreServerAPIClient(signing_key=platform_config.apple_key_bytes,
                                                key_id=platform_config.apple_key_id,
                                                issuer_id=platform_config.apple_issuer_id,
                                                bundle_id=platform_config.apple_bundle_id,
                                                environment=apple_env)

    apple_verifier   = AppleSignedDataVerifier(root_certificates=platform_config.apple_root_certs,
                                               enable_online_checks=True,
                                               environment=apple_env,
                                               bundle_id=platform_config.apple_bundle_id,
                                               app_apple_id=app_apple_id)

    try:
        response_test_notif: AppleSendTestNotificationResponse = apple_client.request_test_notification()
        print("Send test notif: ", response_test_notif)

        notification_token = response_test_notif.testNotificationToken
        if notification_token:
            response_check_test_notif: AppleCheckTestNotificationResponse = apple_client.get_test_notification_status(test_notification_token=notification_token)
            print("Check test notif: ", response_check_test_notif)
            if response_check_test_notif.signedPayload:
                decoded_response: AppleResponseBodyV2DecodedPayload = apple_verifier.verify_and_decode_notification(signed_payload=response_check_test_notif.signedPayload)
                print('Decoded test response: ', decoded_response)
    except AppleAPIException as e:
        print(e)

def sub_duration_s_from_response_body_v2(notif_type: AppleNotificationV2, body: AppleJWSTransactionDecodedPayload, err: base.ErrorSink) -> int | None:
    result: int | None = None

    all_fields_set: bool  = False
    all_fields_set       |= require_field(body.bundleId,  f'Apple notification {notif_type} is missing bundle ID from payload', err)
    all_fields_set       |= require_field(body.productId, f'Apple notification {notif_type} is missing product ID from payload', err)
    if not all_fields_set:
        return result

    # NOTE: Assert the types for LSP now that we have checked that they exist
    assert isinstance(body.bundleId, str)
    assert isinstance(body.productId, str)

    # NOTE: Verify the bundle ID
    if body.bundleId != platform_config.apple_bundle_id:
        err.msg_list.append(f'Apple notification {notif_type} bundle ID \'{body.bundleId}\' did not match expected \'{platform_config.apple_bundle_id}\'')
        return result

    # NOTE: Convert product ID to duration
    if body.productId == 'com.getsession.org.pro_sub':
        result = 365 * base.SECONDS_IN_DAY
    else:
        err.msg_list.append(f'Apple notification {notif_type} specified unrecognised \'{body.productId}\'')

    return result

def maybe_get_apple_jws_transaction_from_response_body_v2(body: AppleResponseBodyV2DecodedPayload, verifier: AppleSignedDataVerifier, err: base.ErrorSink | None) -> AppleJWSTransactionDecodedPayload | None:
    raw_tx: str | None = None
    if require_field(body.data, f'{body.notificationType} notification is missing body\'s data', err):
        assert isinstance(body.data, AppleData)
        if require_field(body.data.signedTransactionInfo, f'{body.notificationType} notification is missing body data\'s signedTransactionInfo', err):
            assert isinstance(body.data.signedTransactionInfo, str)
            raw_tx = body.data.signedTransactionInfo

    # Parse and verify the raw TX
    result: AppleJWSTransactionDecodedPayload | None = None
    if raw_tx:
        try:
            result = verifier.verify_and_decode_signed_transaction(raw_tx)
        except AppleVerificationException as e:
            if err:
                err.msg_list.append(f'{body.notificationType} notification signed TX data failed to be verified, {e}')

    return result

def handle_notification(verifier: AppleSignedDataVerifier, body: AppleResponseBodyV2DecodedPayload, sql_conn: sqlite3.Connection):
    # NOTE: Exhaustively handle all the notification types defined by Apple:
    #
    #   Notification Types
    #     https://developer.apple.com/documentation/appstoreservernotifications/notificationtype
    #   Notification Sub-types
    #     https://developer.apple.com/documentation/appstoreservernotifications/subtype

    # NOTE: Apple provides multiple IDs for the transaction that are guaranteed to be
    # unique. They all have different purposes with different lifetimes.
    #
    #   transactionId
    #     The App Store generates a new value for transaction identifier every time the
    #     subscription automatically renews or the user restores it on a new device.
    #
    #     When a user first purchases a subscription, the transaction identifier always
    #     matches the original transaction identifier (originalTransactionId). For a restore
    #     or renewal, the transaction identifier doesn’t match the original transaction
    #     identifier. If a user restores or renews the same subscription multiple times,
    #     each restore or renewal has a unique transaction identifier.
    #
    #   originalTransactionId
    #     This value is identical to the transaction identifier (transactionId) except when
    #     the user restores or renews a subscription.
    #
    #     This field uniquely identifies a subscription, rather than a single subscription
    #     renewal purchase. Across any number of subscription renewals, billing retry and
    #     grace periods, and periods where the user unsubscribed, this value will remain
    #     constant for a given user and subscription product pairing.
    #
    #   webOrderLineItemId
    #     The unique identifier of subscription purchase events across devices, including
    #     subscription renewals.
    #
    #     It is an identifier of a completed subscription renewal purchase. For an
    #     auto-renewing monthly subscription, a purchase is made once per month to renew the
    #     subscription. Each monthly purchase will have its own webOrderLineItemId. Even if
    #     the user accesses their subscription from multiple devices or restores purchases,
    #     this webOrderLineItemId is the same, since it's tied to their month's purchase of
    #     the subscription entitlement.
    #
    #   See this page and related for the source and more meta information:
    #
    #     https://developer.apple.com/documentation/appstoreservernotifications/transactionid
    #     https://developer.apple.com/forums/thread/711952
    #     https://developer.apple.com/forums/thread/726541
    #
    # In order to cover all the possible cases, we preserve all the transaction IDs into the
    # backend so that we can handle all the different scenarios Apple can notify us with because
    # their notifications about the same semantic subscription might only have 1 or more of these
    # IDs in commonality.

    # NOTE: There's only one v2 notfication sent per event triggered by the user. For example an
    # upgrade of a subscription is implemented by refunding the pro-rata amount followed by
    # upgrading the subscription. One event is issued for this, a DID_CHANGE_RENEWL_PREF with an
    # UPGRADE subtype instead of 2 notifications i.e.: 1 refund and 1 upgrade notification.
    #
    # Source
    #   https://developer.apple.com/forums/thread/719657?answerId=735817022#735817022
    #   https://developer.apple.com/forums/thread/735297?answerId=761269022#761269022

    err            = base.ErrorSink()
    unix_ts_s: int = int(time.time())
    if body.notificationType == AppleNotificationV2.SUBSCRIBED       or \
       body.notificationType == AppleNotificationV2.DID_RENEW        or \
       body.notificationType == AppleNotificationV2.ONE_TIME_CHARGE:
        # AppleNotificationV2.ONE_TIME_CHARGE
        #   A notification type that indicates the customer purchased a consumable, non-consumable, or
        #   non-renewing subscription. The App Store also sends this notification when the customer
        #   receives access to a non-consumable product through Family Sharing.
        #
        #   For notifications about auto-renewable subscription purchases, see the SUBSCRIBED
        #   notification type.
        #
        #   User bought a subscription, but, didn't set it to auto-renew. Note we should never get a
        #   consumable here as we don't support those.
        #
        #   Triggers (https://developer.apple.com/documentation/appstoreservernotifications/notificationtype#Handle-use-cases-for-in-app-purchase-life-cycle-events)
        #     Customer purchases a consumable, non-consumable, or non-renewing subscription.
        #     Customer receives access to a non-consumable in-app purchase through Family Sharing.
        #
        # AppleNotificationV2.SUBSCRIBED
        #   A notification type that, along with its subtype, indicates that the customer subscribed
        #   to an auto-renewable subscription. If the subtype is INITIAL_BUY, the customer either
        #   purchased or received access through Family Sharing to the subscription for the first
        #   time. If the subtype is RESUBSCRIBE, the user resubscribed or received access through
        #   Family Sharing to the same subscription or to another subscription within the same
        #   subscription group.
        #
        #   For notifications about other product type purchases, see the ONE_TIME_CHARGE notification
        #   type.
        #
        #   Triggers (https://developer.apple.com/documentation/appstoreservernotifications/notificationtype#Handle-use-cases-for-in-app-purchase-life-cycle-events)
        #     Customer subscribes for the first time to any subscription within a subscription group. (subtype INITIAL_BUY)
        #     Customer resubscribes to any subscription from the same subscription group as their expired subscription. (subtype RESUBSCRIBE)
        #     A family member gains access to the subscription through Family Sharing after the purchaser subscribes for the first time. (subtype INITIAL_BUY)
        #     A family member gains access to the subscription through Family Sharing after the purchaser resubscribes. (subtype RESUBSCRIBE)
        #     Customer redeems an offer code to subscribe for the first time. (subtype INITIAL_BUY)
        #     Customer redeems a promotional offer, offer code, or win-back offer after their subscription expired. (subtype RESUBSCRIBE)
        #
        # AppleNotifiationV2.DID_RENEW
        #   A notification type that, along with its subtype, indicates that the subscription
        #   successfully renewed. If the subtype is BILLING_RECOVERY, the expired subscription that
        #   previously failed to renew has successfully renewed. If the subtype is empty, the active
        #   subscription has successfully auto-renewed for a new transaction period. Provide the
        #   customer with access to the subscription’s content or service.
        #
        #   Triggers
        #     The subscription successfully auto-renews.
        #     The billing retry successfully recovers the subscription. (subtype BILLING_RECOVERY)
        tx: AppleJWSTransactionDecodedPayload | None = maybe_get_apple_jws_transaction_from_response_body_v2(body, verifier, err)
        if tx:
            if require_field(tx.expiresDate,           f'{body.notificationType} is missing TX expires date. TX was {json.dumps(tx, indent=1)}',            err) and \
               require_field(tx.originalTransactionId, f'{body.notificationType} is missing TX original transaction ID. TX was {json.dumps(tx, indent=1)}', err) and \
               require_field(tx.originalPurchaseDate,  f'{body.notificationType} is missing TX original purchase date. TX was {json.dumps(tx, indent=1)}',  err) and \
               require_field(tx.transactionId,         f'{body.notificationType} is missing TX transaction ID. TX was {json.dumps(tx, indent=1)}',          err) and \
               require_field(tx.transactionReason,     f'{body.notificationType} is missing TX reason. TX was {json.dumps(tx, indent=1)}',                  err) and \
               require_field(tx.type,                  f'{body.notificationType} is missing TX type. TX was {json.dumps(tx, indent=1)}',                    err) and \
               require_field(tx.webOrderLineItemId,    f'{body.notificationType} is missing TX web order line item ID. TX was {json.dumps(tx, indent=1)}',  err):

                # NOTE: Assert the types for LSP now that we have checked that they exist
                assert isinstance(tx.originalPurchaseDate,  int)
                assert isinstance(tx.originalTransactionId, str)
                assert isinstance(tx.transactionId,         str)
                assert isinstance(tx.expiresDate,           str)
                assert isinstance(tx.transactionReason,     AppleTransactionReason)
                assert isinstance(tx.type,                  AppleType)
                assert isinstance(tx.webOrderLineItemId,    str)

                if body.notificationType == AppleNotificationV2.ONE_TIME_CHARGE:
                    # NOTE: Verify that the TX type is what we expect it to be
                    expected_type = AppleType.NON_RENEWING_SUBSCRIPTION
                    if tx.type != expected_type:
                        err.msg_list.append(f'{body.notificationType} TX type ({tx.type}) was not the expected value: {expected_type}. TX was {json.dumps(tx, indent=1)}')

                    # NOTE: Verify purchase type is what we expect it to be
                    expected_reason = AppleTransactionReason.PURCHASE
                    if tx.transactionReason != expected_reason:
                        err.msg_list.append(f'{body.notificationType} TX type ({tx.transactionReason}) was not the expected value for a one-time payment: {expected_reason}. TX was {json.dumps(tx, indent=1)}')
                else:
                    # NOTE: Verify that the TX type is what we expect it to be
                    expected_type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
                    if tx.type != expected_type:
                        err.msg_list.append(f'{body.notificationType} TX type ({tx.type}) was not the expected value: {expected_type}. TX was {json.dumps(tx, indent=1)}')

                # NOTE: Extract duration
                subscription_duration_s: int | None = sub_duration_s_from_response_body_v2(body.notificationType, tx, err)

                # NOTE: Process notification
                if len(err.msg_list) == 0:
                    assert isinstance(subscription_duration_s, int)
                    backend.add_unredeemed_apple_payment(sql_conn                   = sql_conn,
                                                         apple_tx_id                = tx.originalTransactionId,
                                                         apple_original_tx_id       = tx.transactionId,
                                                         apple_web_line_order_tx_id = tx.webOrderLineItemId,
                                                         subscription_duration_s    = subscription_duration_s,
                                                         payment_provider           = base.PaymentProvider.iOSAppStore,
                                                         err                        = err)

    elif body.notificationType == AppleNotificationV2.DID_CHANGE_RENEWAL_PREF:
        # A notification type that, along with its subtype, indicates that the customer made a
        # change to their subscription plan. If the subtype is UPGRADE, the user upgraded their
        # subscription. The upgrade goes into effect immediately, starting a new billing period,
        # and the user receives a prorated refund for the unused portion of the previous period. If
        # the subtype is DOWNGRADE, the customer downgraded their subscription. Downgrades take
        # effect at the next renewal date and don’t affect the currently active plan.
        #
        # If the subtype is empty, the user changed their renewal preference back to the current
        # subscription, effectively canceling a downgrade.
        #
        # Triggers (https://developer.apple.com/documentation/appstoreservernotifications/notificationtype#Handle-use-cases-for-in-app-purchase-life-cycle-events)
        #   Customer downgrades a subscription within the same subscription group. (subtype DOWNGRADE)
        #   Customer reverts to the previous subscription, effectively canceling their downgrade.
        #   Customer upgrades a subscription within the same subscription group. (subtype UPGRADE)
        tx: AppleJWSTransactionDecodedPayload | None = maybe_get_apple_jws_transaction_from_response_body_v2(body, verifier, err)
        if tx:
            if require_field(tx.expiresDate,           f'{body.notificationType} is missing TX expires date. TX was {json.dumps(tx, indent=1)}',            err) and \
               require_field(tx.originalTransactionId, f'{body.notificationType} is missing TX original transaction ID. TX was {json.dumps(tx, indent=1)}', err) and \
               require_field(tx.originalPurchaseDate,  f'{body.notificationType} is missing TX original purchase date. TX was {json.dumps(tx, indent=1)}',  err) and \
               require_field(tx.transactionId,         f'{body.notificationType} is missing TX transaction ID. TX was {json.dumps(tx, indent=1)}',          err) and \
               require_field(tx.transactionReason,     f'{body.notificationType} is missing TX reason. TX was {json.dumps(tx, indent=1)}',                  err) and \
               require_field(tx.type,                  f'{body.notificationType} is missing TX type. TX was {json.dumps(tx, indent=1)}',                    err) and \
               require_field(tx.webOrderLineItemId,    f'{body.notificationType} is missing TX web order line item ID. TX was {json.dumps(tx, indent=1)}',  err):

                # NOTE: Assert the types for LSP now that we have checked that they exist
                assert isinstance(tx.originalPurchaseDate,  int)
                assert isinstance(tx.originalTransactionId, str)
                assert isinstance(tx.transactionId,         str)
                assert isinstance(tx.expiresDate,           str)
                assert isinstance(tx.transactionReason,     AppleTransactionReason)
                assert isinstance(tx.type,                  AppleType)
                assert isinstance(tx.webOrderLineItemId,    str)

                # NOTE: Verify that the TX type is what we expect it to be
                expected_type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
                if tx.type != expected_type:
                    err.msg_list.append(f'{body.notificationType} TX type ({tx.type}) was not the expected value: {expected_type}. TX was {json.dumps(tx, indent=1)}')

                # NOTE: Extract duration
                subscription_duration_s: int | None = sub_duration_s_from_response_body_v2(body.notificationType, tx, err)

                # NOTE: Extract components
                if len(err.msg_list) == 0:
                    assert isinstance(subscription_duration_s, int)
                    if not body.subtype:
                        # User is cancelling their upgrade. End the current subscription and revive the old subscription
                        # TODO: Err, how do I find the "previous" subscription and re-activate it.
                        backend.revert_apple_payment(sql_conn, tx.originalTransactionId)

                    elif body.subtype == AppleSubtype.DOWNGRADE:
                        # NOTE: User is downgrading to a lesser subscription. Downgrade happens at
                        # end of billing cycle. This is a no-op, we _should_ get a DID_RENEW
                        # notification which handles this for us.
                        pass
                    elif body.subtype == AppleSubtype.UPGRADE:
                        # User is upgrading to a better subscription. Upgrade happens immediately, current plan is ended.
                        # NOTE: The only link we have to the current plan is the original transaction ID, so we use that
                        # to cancel the old payment and issue a new one.
                        backend.delete_apple_payment(sql_conn=sql_conn,
                                                     apple_web_line_order_tx_id=tx.webOrderLineItemId,
                                                     apple_original_tx_id=tx.originalTransactionId,
                                                     archived_unix_ts_s=unix_ts_s)

                        # TODO: Submit/upgrade the payment
                        backend.add_unredeemed_apple_payment(sql_conn                   = sql_conn,
                                                             apple_tx_id                = tx.originalTransactionId,
                                                             apple_original_tx_id       = tx.transactionId,
                                                             apple_web_line_order_tx_id = tx.webOrderLineItemId,
                                                             subscription_duration_s    = subscription_duration_s,
                                                             payment_provider           = base.PaymentProvider.iOSAppStore,
                                                             err                        = err)

    elif body.notificationType == AppleNotificationV2.OFFER_REDEEMED:
        # A notification type that, along with its subtype, indicates that a customer with an active
        # subscription redeemed a subscription offer.
        #
        # If the subtype is UPGRADE, the customer redeemed an offer to upgrade their active
        # subscription, which goes into effect immediately. If the subtype is DOWNGRADE, the
        # customer redeemed an offer to downgrade their active subscription, which goes into effect
        # at the next renewal date. If the customer redeemed an offer for their active subscription,
        # you receive an OFFER_REDEEMED notification type without a subtype.
        #
        # Triggers (https://developer.apple.com/documentation/appstoreservernotifications/notificationtype#Handle-use-cases-for-in-app-purchase-life-cycle-events)
        #   Customer redeems a promotional offer or offer code for an active subscription.
        #   Customer redeems a promotional offer or offer code to upgrade their subscription. (subtype UPGRADE)
        #   Customer redeems a promotional offer and downgrades their subscription. (subtype DOWNGRADE)
        #
        tx: AppleJWSTransactionDecodedPayload | None = maybe_get_apple_jws_transaction_from_response_body_v2(body, verifier, err)
        if tx:
            if require_field(tx.expiresDate,           f'{body.notificationType} is missing TX expires date. TX was {json.dumps(tx, indent=1)}',            err) and \
               require_field(tx.originalTransactionId, f'{body.notificationType} is missing TX original transaction ID. TX was {json.dumps(tx, indent=1)}', err) and \
               require_field(tx.originalPurchaseDate,  f'{body.notificationType} is missing TX original purchase date. TX was {json.dumps(tx, indent=1)}',  err) and \
               require_field(tx.transactionId,         f'{body.notificationType} is missing TX transaction ID. TX was {json.dumps(tx, indent=1)}',          err) and \
               require_field(tx.transactionReason,     f'{body.notificationType} is missing TX reason. TX was {json.dumps(tx, indent=1)}',                  err) and \
               require_field(tx.type,                  f'{body.notificationType} is missing TX type. TX was {json.dumps(tx, indent=1)}',                    err) and \
               require_field(tx.webOrderLineItemId,    f'{body.notificationType} is missing TX web order line item ID. TX was {json.dumps(tx, indent=1)}',  err):

                # NOTE: Assert the types for LSP now that we have checked that they exist
                assert isinstance(tx.originalPurchaseDate,  int)
                assert isinstance(tx.originalTransactionId, str)
                assert isinstance(tx.transactionId,         str)
                assert isinstance(tx.expiresDate,           str)
                assert isinstance(tx.transactionReason,     AppleTransactionReason)
                assert isinstance(tx.type,                  AppleType)
                assert isinstance(tx.webOrderLineItemId,    str)

                # NOTE: Verify that the TX type is what we expect it to be
                expected_type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
                if tx.type != expected_type:
                    err.msg_list.append(f'{body.notificationType} TX type ({tx.type}) was not the expected value: {expected_type}. TX was {json.dumps(tx, indent=1)}')

                # NOTE: Extract duration
                subscription_duration_s: int | None = sub_duration_s_from_response_body_v2(body.notificationType, tx, err)

                # NOTE: Extract components
                if len(err.msg_list) == 0:
                    assert isinstance(subscription_duration_s, int)
                    if not body.subtype:
                        # NOTE: User is redeeming an offer to start(?) a sub. Submit the payment
                        backend.add_unredeemed_apple_payment(sql_conn                   = sql_conn,
                                                             apple_tx_id                = tx.originalTransactionId,
                                                             apple_original_tx_id       = tx.transactionId,
                                                             apple_web_line_order_tx_id = tx.webOrderLineItemId,
                                                             subscription_duration_s    = subscription_duration_s,
                                                             payment_provider           = base.PaymentProvider.iOSAppStore,
                                                             err                        = err)
                    elif body.subtype == AppleSubtype.DOWNGRADE:
                        # NOTE: User is downgrading to a lesser subscription. Downgrade happens at
                        # end of billing cycle. This is a no-op, we _should_ get a DID_RENEW
                        # notification which handles this for us at the end of the month when they
                        # renew.
                        pass
                    elif body.subtype == AppleSubtype.UPGRADE:
                        # NOTE User is upgrading to a better subscription. Upgrade happens
                        # immediately, current plan is ended. The only link we have to the current
                        # plan is the original transaction ID, so we use that to cancel the old
                        # payment and issue a new one.
                        backend.delete_apple_payment(sql_conn=sql_conn,
                                                     apple_web_line_order_tx_id=tx.webOrderLineItemId,
                                                     apple_original_tx_id=tx.originalTransactionId,
                                                     archived_unix_ts_s=unix_ts_s)

                        # TODO: Submit the "new" payment
                        backend.add_unredeemed_apple_payment(sql_conn                   = sql_conn,
                                                             apple_tx_id                = tx.originalTransactionId,
                                                             apple_original_tx_id       = tx.transactionId,
                                                             apple_web_line_order_tx_id = tx.webOrderLineItemId,
                                                             subscription_duration_s    = subscription_duration_s,
                                                             payment_provider           = base.PaymentProvider.iOSAppStore,
                                                             err                        = err)

    elif body.notificationType == AppleNotificationV2.REFUND or body.notificationType == AppleNotificationV2.REVOKE:
        # AppleNotificationV2.REFUND
        #   A notification type that indicates that the App Store successfully refunded a transaction
        #   for a consumable in-app purchase, a non-consumable in-app purchase, an auto-renewable
        #   subscription, or a non-renewing subscription.
        #
        #   The revocationDate contains the timestamp of the refunded transaction. The
        #   originalTransactionId and productId identify the original transaction and product. The
        #   revocationReason contains the reason.
        #
        #   Triggers (https://developer.apple.com/documentation/appstoreservernotifications/notificationtype#Handle-use-cases-for-in-app-purchase-life-cycle-events)
        #     Apple refunds the transaction for a consumable or non-consumable in-app purchase, a non-renewing subscription, or an auto-renewable subscription.
        #
        # AppleNotificationV2.REVOKE
        #   A notification type that indicates that an in-app purchase the customer was entitled to
        #   through Family Sharing is no longer available through sharing. The App Store sends this
        #   notification when a purchaser disables Family Sharing for their purchase, the purchaser
        #   (or family member) leaves the family group, or the purchaser receives a refund. Your app
        #   also receives a paymentQueue(_:didRevokeEntitlementsForProductIdentifiers:) call. Family
        #   Sharing applies to non-consumable in-app purchases and auto-renewable subscriptions. For
        #   more information about Family Sharing, see Supporting Family Sharing in your app.
        #
        #   Triggers (https://developer.apple.com/documentation/appstoreservernotifications/notificationtype#Handle-use-cases-for-in-app-purchase-life-cycle-events)
        #     A family member loses access to the subscription through Family Sharing.
        tx: AppleJWSTransactionDecodedPayload | None = maybe_get_apple_jws_transaction_from_response_body_v2(body, verifier, err)
        if tx:
            if require_field(tx.expiresDate,           f'{body.notificationType} is missing TX expires date. TX was {json.dumps(tx, indent=1)}',            err) and \
               require_field(tx.originalTransactionId, f'{body.notificationType} is missing TX original transaction ID. TX was {json.dumps(tx, indent=1)}', err) and \
               require_field(tx.transactionId,         f'{body.notificationType} is missing TX transaction ID. TX was {json.dumps(tx, indent=1)}',          err) and \
               require_field(tx.transactionReason,     f'{body.notificationType} is missing TX reason. TX was {json.dumps(tx, indent=1)}',                  err) and \
               require_field(tx.type,                  f'{body.notificationType} is missing TX type. TX was {json.dumps(tx, indent=1)}',                    err):

                # NOTE: Assert the types for LSP now that we have checked that they exist
                assert isinstance(tx.expiresDate,           str)
                assert isinstance(tx.originalTransactionId, str)
                assert isinstance(tx.transactionId,         str)
                assert isinstance(tx.transactionReason,     AppleTransactionReason)
                assert isinstance(tx.type,                  AppleType)

                # NOTE: Extract components
                if len(err.msg_list) == 0:
                    backend.delete_apple_payment(sql_conn=sql_conn,
                                                 apple_web_line_order_tx_id=tx.webOrderLineItemId,
                                                 apple_original_tx_id=tx.originalTransactionId,
                                                 archived_unix_ts_s=unix_ts_s)

    elif body.notificationType == AppleNotificationV2.REFUND_REVERSED:
        # A notification type that indicates the App Store reversed a previously granted refund due
        # to a dispute that the customer raised. If your app revoked content or services as a result
        # of the related refund, it needs to reinstate them.
        #
        # This notification type can apply to any in-app purchase type: consumable, non-consumable,
        # non-renewing subscription, and auto-renewable subscription. For auto-renewable
        # subscriptions, the renewal date remains unchanged when the App Store reverses a refund.
        #
        # Triggers (https://developer.apple.com/documentation/appstoreservernotifications/notificationtype#Handle-use-cases-for-in-app-purchase-life-cycle-events)
        #   Apple reverses a previously granted refund due to a dispute that the customer raised.
        tx: AppleJWSTransactionDecodedPayload | None = maybe_get_apple_jws_transaction_from_response_body_v2(body, verifier, err)
        if tx:
            if require_field(tx.expiresDate,           f'{body.notificationType} is missing TX expires date. TX was {json.dumps(tx, indent=1)}',            err) and \
               require_field(tx.originalTransactionId, f'{body.notificationType} is missing TX original transaction ID. TX was {json.dumps(tx, indent=1)}', err) and \
               require_field(tx.transactionId,         f'{body.notificationType} is missing TX transaction ID. TX was {json.dumps(tx, indent=1)}',          err) and \
               require_field(tx.transactionReason,     f'{body.notificationType} is missing TX reason. TX was {json.dumps(tx, indent=1)}',                  err) and \
               require_field(tx.type,                  f'{body.notificationType} is missing TX type. TX was {json.dumps(tx, indent=1)}',                    err):

                # NOTE: Assert the types for LSP now that we have checked that they exist
                assert isinstance(tx.expiresDate,           str)
                assert isinstance(tx.originalTransactionId, str)
                assert isinstance(tx.transactionId,         str)
                assert isinstance(tx.transactionReason,     AppleTransactionReason)
                assert isinstance(tx.type,                  AppleType)

                # NOTE: Extract components
                if len(err.msg_list) == 0:
                    backend.delete_apple_payment(sql_conn=sql_conn,
                                                 apple_web_line_order_tx_id=tx.webOrderLineItemId,
                                                 apple_original_tx_id=tx.originalTransactionId,
                                                 archived_unix_ts_s=unix_ts_s)


    elif body.notificationType == AppleNotificationV2.DID_CHANGE_RENEWAL_STATUS:
        # A notification type that, along with its subtype, indicates that the customer made a
        # change to the subscription renewal status. If the subtype is AUTO_RENEW_ENABLED, the
        # customer reenabled subscription auto-renewal. If the subtype is AUTO_RENEW_DISABLED, the
        # customer turned off subscription auto-renewal, or the App Store turned off subscription
        # auto-renewal after the customer requested a refund.
        #
        # Triggers (https://developer.apple.com/documentation/appstoreservernotifications/notificationtype#Handle-use-cases-for-in-app-purchase-life-cycle-events)
        #
        # TODO: Update the user's renewal status. Necessary to so that cross-platform devices
        # know and can display to the user if they have a renewing subscription. I'm not sure what
        # data comes through here yet.
        tx: AppleJWSTransactionDecodedPayload | None = maybe_get_apple_jws_transaction_from_response_body_v2(body, verifier, err)
        if tx:
            err.msg_list.append(f'Received TX: {tx}, TODO: this needs to be handled but first check what data we got')

    elif body.notificationType == AppleNotificationV2.DID_FAIL_TO_RENEW:
        # A notification type that, along with its subtype, indicates that the subscription failed
        # to renew due to a billing issue. The subscription enters the billing retry period. If the
        # subtype is GRACE_PERIOD, continue to provide service through the grace period. If the
        # subtype is empty, the subscription isn’t in a grace period and you can stop providing the
        # subscription service.
        #
        # Inform the customer that there may be an issue with their billing information. The App
        # Store continues to retry billing for 60 days, or until the customer resolves their billing
        # issue or cancels their subscription, whichever comes first.
        #
        # Triggers (https://developer.apple.com/documentation/appstoreservernotifications/notificationtype#Handle-use-cases-for-in-app-purchase-life-cycle-events)
        #
        # TODO: Potentially have to pass on information to the backend so cross-platform devices can
        # identify that there's a renewing issue.
        tx: AppleJWSTransactionDecodedPayload | None = maybe_get_apple_jws_transaction_from_response_body_v2(body, verifier, err)
        if tx:
            err.msg_list.append(f'Received TX: {tx}, TODO: this needs to be handled but first check what data we got')

    elif body.notificationType == AppleNotificationV2.TEST:
        # NOTE: Test notification that we can invoke for testing. No-op
        pass

    # NOTE: Notifications that we do not care about handling
    elif body.notificationType == AppleNotificationV2.EXPIRED              or \
         body.notificationType == AppleNotificationV2.REFUND_DECLINED      or \
         body.notificationType == AppleNotificationV2.GRACE_PERIOD_EXPIRED or \
         body.notificationType == AppleNotificationV2.CONSUMPTION_REQUEST  or \
         body.notificationType == AppleNotificationV2.PRICE_INCREASE:

        if body.notificationType == AppleNotificationV2.EXPIRED:
            # A notification type that, along with its subtype, indicates that a subscription
            # expired. If the subtype is VOLUNTARY, the subscription expired after the customer
            # turned off subscription renewal. If the subtype is BILLING_RETRY, the subscription
            # expired because the billing retry period ended without a successful billing
            # transaction. If the subtype is PRICE_INCREASE, the subscription expired because the
            # customer didn’t consent to a price increase that requires customer consent. If the
            # subtype is PRODUCT_NOT_FOR_SALE, the subscription expired because the product wasn’t
            # available for purchase at the time the subscription attempted to renew.
            #
            # A notification without a subtype indicates that the subscription expired for some
            # other reason.
            #
            # Triggers (https://developer.apple.com/documentation/appstoreservernotifications/notificationtype#Handle-use-cases-for-in-app-purchase-life-cycle-events)
            #
            # NOTE: No-op, the Session Pro proof already has a baked in expiry date and will
            # self-expire itself.
            pass

        elif body.notificationType == AppleNotificationV2.REFUND_DECLINED:
            # A notification type that indicates the App Store declined a refund request.
            #
            # NOTE: No-op, the user is still entitled to Session Pro
            pass

        elif body.notificationType == AppleNotificationV2.GRACE_PERIOD_EXPIRED:
            # A notification type that indicates that the billing grace period has ended without
            # renewing the subscription, so you can turn off access to the service or content. Inform
            # the customer that there may be an issue with their billing information. The App Store
            # continues to retry billing for 60 days, or until the customer resolves their billing issue
            # or cancels their subscription, whichever comes first.
            #
            # Triggers (https://developer.apple.com/documentation/appstoreservernotifications/notificationtype#Handle-use-cases-for-in-app-purchase-life-cycle-events)
            #
            # TODO: No-op, the Session Pro proofs have an expiry date embedded into them and that is
            # handled by the backend itself.
            pass

        elif body.notificationType == AppleNotificationV2.CONSUMPTION_REQUEST:
            # A notification type that indicates that the customer initiated a refund request for
            # a consumable in-app purchase or auto-renewable subscription, and the App Store is
            # requesting that you provide consumption data. For more information, see Send Consumption
            # Information.
            #
            # Triggers (https://developer.apple.com/documentation/appstoreservernotifications/notificationtype#Handle-use-cases-for-in-app-purchase-life-cycle-events)
            #   Apple requests consumption information for a refund request that a customer initiates.
            #
            # NOTE: We do not provide consumption data because we don't have some sort of credit system
            # that a user can expend whilst on the subscription. Furthermore, sending a consumption
            # request-response requires getting consent from the user:
            #
            #   type customerConsented
            #     A Boolean value that indicates whether the customer consented to provide consumption data to the App Store.
            #
            # We avoid all this because all we need to do when a user refunds is cancel their membership
            # by issueing a revocation by the backend.
            pass

        else: # Price increase
            assert body.notificationType == AppleNotificationV2.PRICE_INCREASE
            # A notification type that, along with its subtype, indicates that the system has
            # informed the customer of an auto-renewable subscription price increase.
            #
            # If the price increase requires customer consent, the subtype is PENDING if the
            # customer hasn’t responded to the price increase, or ACCEPTED if the customer has
            # consented to the price increase.
            #
            # If the price increase doesn’t require customer consent, the subtype is ACCEPTED.
            #
            # Triggers (https://developer.apple.com/documentation/appstoreservernotifications/notificationtype#Handle-use-cases-for-in-app-purchase-life-cycle-events)
            #
            # TODO: No-op, the apps do not respond to price increases
            pass


    # NOTE: Erroneous cases, scenarios we don't support/should never receive a notification for
    elif body.notificationType == AppleNotificationV2.EXTERNAL_PURCHASE_TOKEN or \
         body.notificationType == AppleNotificationV2.RENEWAL_EXTENDED        or \
         body.notificationType == AppleNotificationV2.RENEWAL_EXTENSION:

         if body.notificationType == AppleNotificationV2.EXTERNAL_PURCHASE_TOKEN:
            err.msg_list.append(f'Received Apple notification "{body.notificationType}", but we do not support 3rd party stores through Apple')
         elif body.notificationType == AppleNotificationV2.RENEWAL_EXTENSION or body.notificationType == AppleNotificationV2.RENEWAL_EXTENDED:
            err.msg_list.append(f'Received Apple notification "{body.notificationType}", but we don\'t handle issueing the extension of a subscription renewal (e.g.: to compensate for service outages)')
    else:
        err.msg_list.append(f'Received Apple notification {body.notificationType} that wasn\'t explicitly handled')

    if len(err.msg_list):
        err_msg = '\n'.join(err.msg_list)
        print(f'ERROR: {err_msg}\nPayload was: {json.dumps(body, indent=1)}')

entry_point()
