import json
import logging
import os
import sqlite3
import sys

from google.cloud import pubsub_v1
import google.cloud.pubsub_v1.subscriber.message

import backend
import base
from backend import OpenDBAtPath, PaymentProviderTransaction, AddRevocationItem, ProPlanType, UserErrorTransaction
from base import JSONObject, handle_not_implemented, json_dict_require_str, json_dict_require_str_coerce_to_int, os_get_boolean_env, \
    safe_dump_dict_keys_or_data, json_dict_optional_obj, json_dict_require_int_coerce_to_enum, dump_enum_details, obfuscate 

import env

from platform_google_api import SubscriptionPlanTxFields, VoidedPurchaseTxFields, get_subscription_plan_tx_fields, google_api_fetch_subscription_details_for_base_plan_id, google_api_fetch_subscription_v2 
from platform_google_types import SubscriptionNotificationType, SubscriptionsV2SubscriptionAcknowledgementStateType, RefundType, ProductType, SubscriptionV2Data, SubscriptionsV2SubscriptionStateType


def get_pro_plan_type_from_google_base_plan_id(base_plan_id: str, err: base.ErrorSink) -> ProPlanType:
    assert base_plan_id.startswith("session-pro")
    match base_plan_id:
        case "session-pro-1-month":
            return ProPlanType.OneMonth
        case "session-pro-3-months":
            return ProPlanType.ThreeMonth
        case "session-pro-12-months":
            return ProPlanType.TwelveMonth
        case _:
            assert False, f'Invalid google base_plan_id: {base_plan_id}'
            err.msg_list.append(f'Invalid google base_plan_id, unable to determine plan variant: {base_plan_id}')
            return ProPlanType.Nil


def add_user_unredeemed_payment(tx_fields: SubscriptionPlanTxFields, sql_conn: sqlite3.Connection, err: base.ErrorSink):
    """
    Add an unredeemed payment to the database.
    """
    plan = get_pro_plan_type_from_google_base_plan_id(tx_fields.base_plan_id, err)
    
    if err.has():
        return
    
    assert plan is not None and len(tx_fields.order_id) > 0 and len(tx_fields.purchase_token) > 0
    
    tx = PaymentProviderTransaction(
        provider=base.PaymentProvider.GooglePlayStore,
        google_order_id=tx_fields.order_id,
        google_payment_token=tx_fields.purchase_token,
    )

    backend.add_unredeemed_payment(
        sql_conn=sql_conn,
        payment_tx=tx,
        plan=plan,
        expiry_unix_ts_ms=tx_fields.expiry_time.unix_milliseconds,
        unredeemed_unix_ts_ms=tx_fields.event_ts_ms,
        platform_refund_expiry_ts_ms=tx_fields.event_ts_ms + base.MILLISECONDS_IN_DAY * 2,
        err=err,
    )

def _update_payment_renewal_info(purchase_token: str, order_id: str, auto_renewing: bool | None, grace_period_duration_ms: int | None, sql_conn: sqlite3.Connection, err: base.ErrorSink)-> bool:
    assert len(purchase_token) > 0 and len(order_id) > 0 and not err.has()
    tx = PaymentProviderTransaction(
        provider=base.PaymentProvider.GooglePlayStore,
        google_order_id=order_id,
        google_payment_token=purchase_token,
    )

    return backend.update_payment_renewal_info(
        sql_conn=sql_conn,
        payment_tx=tx,
        grace_period_duration_ms=grace_period_duration_ms,
        auto_renewing=auto_renewing,

        err=err,
    )


def toggle_payment_auto_renew(purchase_token: str, order_id: str, auto_renewing: bool, sql_conn: sqlite3.Connection, err: base.ErrorSink):
    success = _update_payment_renewal_info(purchase_token, order_id, auto_renewing, None, sql_conn, err)
    if not success:
        err.msg_list.append(f'Failed to update auto_renew flag for purchase_token: {obfuscate(purchase_token)} and order_id: {obfuscate(order_id)}')

def set_purchase_grace_period_duration(purchase_token: str, order_id: str, grace_period_duration_ms: int, sql_conn: sqlite3.Connection, err: base.ErrorSink):
    success = _update_payment_renewal_info(purchase_token, order_id, None, grace_period_duration_ms, sql_conn, err)
    if not success:
        err.msg_list.append(f'Failed to update grace period duration for purchase_token: {obfuscate(purchase_token)} and order_id: {obfuscate(order_id)}')


def add_user_revocation(order_id: str, sql_conn: sqlite3.Connection):
    """Revoke a pro proof for an order id in the database."""
    assert len(order_id) > 0

    revocation = AddRevocationItem(
        payment_provider=base.PaymentProvider.GooglePlayStore,
        tx_id=order_id,
    )

    backend.add_revocation(
        sql_conn=sql_conn,
        revocation=revocation,
    )


def add_user_canceled_reason(details: SubscriptionV2Data, sql_conn: sqlite3.Connection, err: base.ErrorSink):
    handle_not_implemented('add_user_canceled_reason', err)


def validate_no_existing_purchase_token_error(purchase_token:str, sql_conn: sqlite3.Connection, err: base.ErrorSink):
    result = backend.get_user_error(
        sql_conn=sql_conn,
        provider_id=purchase_token
    )

    if result.provider_id == purchase_token:
        err.msg_list.append(f"Received RTDN notificaiton for already errored purchase token: {obfuscate(purchase_token)}")


def handle_notification_error_with_purchase_token(error_tx: UserErrorTransaction, sql_conn: sqlite3.Connection, err: base.ErrorSink):
    error_tx.provider = base.PaymentProvider.GooglePlayStore
    backend.add_user_error(
        sql_conn=sql_conn,
        error_tx=error_tx,
        err=err
    )


def handle_subscription_notification(tx: SubscriptionPlanTxFields, sql_conn: sqlite3.Connection, err: base.ErrorSink):
    match tx.notification:
        case SubscriptionNotificationType.SUBSCRIPTION_RECOVERED | SubscriptionNotificationType.SUBSCRIPTION_RENEWED:
            # TODO: this needs to be tested, this state happens when you have a successful payment while in grace or account hold, re-activating subscription. It's unclear if a renewed event also happens.
            if tx.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_ACTIVE:
                add_user_unredeemed_payment(tx, sql_conn, err)
                # TODO: we might need to reset the grace period here, will need to see how the grace recovery works with order ids. 

        case SubscriptionNotificationType.SUBSCRIPTION_CANCELED:
            """Google mentions a case where if a user is on account hold and the canceled event happens they should have entitlement revoked, but entitlement is already expired so this does not need to be handled."""
            if tx.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_CANCELED:
                toggle_payment_auto_renew(purchase_token=tx.purchase_token, order_id=tx.order_id, auto_renewing=False, sql_conn=sql_conn, err=err)

        case SubscriptionNotificationType.SUBSCRIPTION_PURCHASED:
            """
            These are the steps documented by Google:
            When a user purchases a subscription, a SubscriptionNotification message with type SUBSCRIPTION_PURCHASED is sent to your RTDN client. Whether you receive this notification or you register a new purchase in-app through PurchasesUpdatedListener or manually fetching purchases in your app's onResume() method, you should process the new purchase in your secure backend. To do this, follow these steps:
            1. Query the purchases.subscriptionsv2.get endpoint to get a subscription resource that contains the latest subscription state.
            2. Make sure that the value of the subscriptionState field is SUBSCRIPTION_STATE_ACTIVE.
            3. Verify the purchase.
            4. Give the user access to the content. The user account associated with the purchase can be identified with the ExternalAccountIdentifiers object from the subscription resource if identifiers were set at purchase time using setObfuscatedAccountId and setObfuscatedProfileId.
            """
            if tx.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_ACTIVE:
                if tx.linked_purchase_token is not None:
                    # TODO: this kinda can fail, and if it does we need to log the error. The revoke + grant should also happen in a single sqlite3 transaction
                    add_user_revocation(tx.order_id, sql_conn)
                    # err.msg_list.append(f'Failed to revoke linked purchase token {obfuscate(details.linked_purchase_token)} associated with new purchase token {obfuscate(purchase_token)}')

                add_user_unredeemed_payment(tx, sql_conn, err)

        case SubscriptionNotificationType.SUBSCRIPTION_ON_HOLD:
            # No entitlement change required
            pass

        case SubscriptionNotificationType.SUBSCRIPTION_IN_GRACE_PERIOD:
            if tx.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_IN_GRACE_PERIOD:
                plan_details = google_api_fetch_subscription_details_for_base_plan_id(tx.base_plan_id, err)
            
                if not err.has():
                    assert plan_details is not None
                    set_purchase_grace_period_duration(purchase_token=tx.purchase_token,
                                                       order_id=tx.order_id,
                                                       grace_period_duration_ms=plan_details.grace_period.milliseconds,
                                                       sql_conn=sql_conn,
                                                       err=err)

        case SubscriptionNotificationType.SUBSCRIPTION_RESTARTED:
            # Only happens when going from CANCELLED to ACTIVE, this is called resubscribing, or re-enabling auto-renew
            if tx.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_ACTIVE:
                toggle_payment_auto_renew(purchase_token=tx.purchase_token, order_id=tx.order_id, auto_renewing=True, sql_conn=sql_conn, err=err)

        case SubscriptionNotificationType.SUBSCRIPTION_PRICE_CHANGE_CONFIRMED:
            # No entitlement change required
            pass

        case SubscriptionNotificationType.SUBSCRIPTION_DEFERRED:
            err.msg_list.append(f'Subscription notificationType {dump_enum_details(tx.notification)} is unsupported!')

        case SubscriptionNotificationType.SUBSCRIPTION_PAUSED:
            err.msg_list.append(f'Subscription notificationType {dump_enum_details(tx.notification)} is unsupported!')

        case SubscriptionNotificationType.SUBSCRIPTION_PAUSE_SCHEDULE_CHANGED:
            err.msg_list.append(f'Subscription notificationType {dump_enum_details(tx.notification)} is unsupported!')

        case SubscriptionNotificationType.SUBSCRIPTION_REVOKED:
            if tx.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_EXPIRED:
                add_user_revocation(tx.order_id, sql_conn)

        case SubscriptionNotificationType.SUBSCRIPTION_EXPIRED:
            # No entitlement change required
            pass

        case SubscriptionNotificationType.SUBSCRIPTION_PRICE_CHANGE_UPDATED:
            # No entitlement change required
            pass

        case SubscriptionNotificationType.SUBSCRIPTION_PENDING_PURCHASE_CANCELED:
            # No entitlement change required
            pass

        case SubscriptionNotificationType.SUBSCRIPTION_PRICE_STEP_UP_CONSENT_UPDATED:
            # No entitlement change required
            pass

        case _:
            err.msg_list.append(f'subscription notificationType is invalid: {dump_enum_details(tx.notification)}')

    if err.has():
        # Purchase token logging is included in the wrapper function
        err.msg_list.append(f'Failed to handle {dump_enum_details(tx.notification)} for order_id {obfuscate(tx.order_id) if len(tx.order_id) > 0 else "N/A"}')
        return

def handle_voided_notification(tx: VoidedPurchaseTxFields, err: base.ErrorSink):
    match tx.product_type:
        case ProductType.PRODUCT_TYPE_SUBSCRIPTION:
            match tx.refund_type:
                case RefundType.REFUND_TYPE_FULL_REFUND:
                    handle_not_implemented(dump_enum_details(tx.refund_type), err)
                case RefundType.REFUND_TYPE_QUANTITY_BASED_PARTIAL_REFUND:
                    # TODO: we need to check if this is actually unsupported, as far as a i can tell it doesn't relate to subscriptions
                    err.msg_list.append(f'voided purchase refundType {dump_enum_details(tx.refund_type)} is unsupported!')
                case _:
                    err.msg_list.append(f'voided purchase refundType is not valid: {dump_enum_details(tx.refund_type)}')
        case ProductType.PRODUCT_TYPE_ONE_TIME:
            err.msg_list.append(f'voided purchase productType {dump_enum_details(tx.product_type)} is unsupported!')
        case _:
            err.msg_list.append(f'voided purchase productType is not valid: {dump_enum_details(tx.product_type)}')

    if err.has():
        err.msg_list.append(f'Failed to handle {dump_enum_details(tx.refund_type) if tx.refund_type is not None else "N/A"} order_id {obfuscate(tx.order_id) if len(tx.order_id) > 0 else "N/A"}')


def handle_notification(body: JSONObject, user_error_tx: UserErrorTransaction, sql_conn: sqlite3.Connection, err: base.ErrorSink):
    body_version = json_dict_require_str(body, "version", err)
    # TODO: Do we want any non debug mode behaviour around mismatched version?
    assert body_version == "1.0"

    package_name = json_dict_require_str(body, "packageName", err)
    event_time_millis = json_dict_require_str_coerce_to_int(body, "eventTimeMillis", err)

    if package_name != platform_config.google_package_name:
        err.msg_list.append(f'{package_name} does not match google_package_name ({platform_config.google_package_name}) from the platform_config!')

    if err.has():
        return

    subscription = json_dict_optional_obj(body, "subscriptionNotification", err)
    one_time_product = json_dict_optional_obj(body, "oneTimeProductNotification", err)
    voided_purchase = json_dict_optional_obj(body, "voidedPurchaseNotification", err)
    test_obj = json_dict_optional_obj(body, "testNotification", err)

    is_subscription_notification = subscription is not None
    is_one_time_product_notification = one_time_product is not None
    is_voided_notification = voided_purchase is not None
    is_test_notification = test_obj is not None

    unique_notif_keys = is_subscription_notification + is_one_time_product_notification + is_voided_notification + is_test_notification

    if unique_notif_keys == 0:
        err.msg_list.append(f'No subscription notification for {package_name} {safe_dump_dict_keys_or_data(body)}')
    elif unique_notif_keys > 1:
        err.msg_list.append(f'Multiple subscription notification for {package_name} {safe_dump_dict_keys_or_data(body)}')

    if err.has():
        return

    if is_subscription_notification:
        purchase_token = json_dict_require_str(subscription, "purchaseToken", err)
        validate_no_existing_purchase_token_error(purchase_token, sql_conn, err)
        if err.has():
            return

        user_error_tx.google_payment_token = purchase_token
        
        version = json_dict_require_str(subscription, "version",  err)
        # TODO: Do we want any non debug mode behaviour around mismatched version?
        assert version == "1.0"

        subscription_notification_type = json_dict_require_int_coerce_to_enum(subscription, "notificationType", SubscriptionNotificationType, err)
        if err.has():
            return

        assert subscription_notification_type is not None
        
        details = google_api_fetch_subscription_v2(package_name, purchase_token, err)

        if err.has():
            err.msg_list.append(f'Parsing subscriptionv2 response for purchase token {obfuscate(purchase_token)} failed')
            return

        assert details is not None

        acknowledgement_state = details.acknowledgement_state
        if acknowledgement_state == SubscriptionsV2SubscriptionAcknowledgementStateType.ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED:
            err.msg_list.append(f'Latest subscription state is already acknowledged')

        if err.has():
            return

        tx_fields = get_subscription_plan_tx_fields(purchase_token, details, event_time_millis, subscription_notification_type, err)
        handle_subscription_notification(tx_fields, sql_conn, err)

    elif is_voided_notification:
        purchase_token = json_dict_require_str(voided_purchase, "purchaseToken", err)
        validate_no_existing_purchase_token_error(purchase_token, sql_conn, err)

        if err.has():
            return

        user_error_tx.google_payment_token = purchase_token

        order_id = json_dict_require_str(voided_purchase, "orderId", err)
        product_type = json_dict_require_int_coerce_to_enum(voided_purchase, "productType", ProductType, err)
        refund_type = json_dict_require_int_coerce_to_enum(voided_purchase, "refundType", RefundType, err)

        assert refund_type is not None and product_type is not None and len(purchase_token) > 0 and len(order_id) > 0
        tx = VoidedPurchaseTxFields(
            purchase_token=purchase_token,
            order_id=order_id,
            event_ts_ms=event_time_millis,
            product_type=product_type,
            refund_type=refund_type,
        )
        handle_voided_notification(tx, err)

    elif is_one_time_product_notification:
        err.msg_list.append(f'one time product is not supported!')

    elif is_test_notification:
        print(f'test payload was: {safe_dump_dict_keys_or_data(body)}')


# NOTE: Enforce the presence of platform_config.py and the variables required for Google
# integration
try:
    import platform_config
    import_error = False
    if not hasattr(platform_config, 'google_package_name') or not isinstance(platform_config.google_package_name, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        print("ERROR: Missing 'google_package_name' string in platform_config.py")
        import_error = True

    if import_error:
        raise ImportError

except ImportError:
    print('''ERROR: 'platform_config.py' is not present or missing fields. Create and fill it e.g.:
      ```python
      import pathlib
      google_package_name: str      = '<google_package_name>'
      ```
    ''')
    sys.exit(1)

def callback(message: google.cloud.pubsub_v1.subscriber.message.Message):
    err = base.ErrorSink()

    body = json.loads(message.data)
    if isinstance(body, dict):
        error_tx = UserErrorTransaction()
        with OpenDBAtPath(env.SESH_PRO_BACKEND_DB_PATH) as db:
            handle_notification(body, error_tx, db.sql_conn, err)
            if err.has() and error_tx.google_payment_token != "":
                # TODO: this logic should probably be inside of handle_notification
                err.msg_list.append(f'Failed to process event for purchase token: {obfuscate(error_tx.google_payment_token)}')
                # We need to use an error sink for any internal errors, but we expect the main sink to have errors
                # so we need a temporary sink for the handler function
                err_internal = base.ErrorSink()
                handle_notification_error_with_purchase_token(error_tx, db.sql_conn, err_internal)
                if err_internal.has():
                    err.msg_list.extend(err_internal.msg_list)
    else:
        err.msg_list.append("Message data is not a valid JSON object!")

    if err.has():
        err_msg = '\n'.join(err.msg_list)
        logging.error(f'ERROR: {err_msg}\nPayload was: {safe_dump_dict_keys_or_data(body)}\n')
    else:
        print(f'ACK')
        message.ack()

def entry_point():
    # TODO: these env parsers are needed here if used as an entry point, they need to be removed if/when this changes
    env.GOOGLE_APPLICATION_CREDENTIALS = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')

    if not env.GOOGLE_APPLICATION_CREDENTIALS:
        raise ValueError("GOOGLE_APPLICATION_CREDENTIALS environment variable not set")

    if not os.path.exists(env.GOOGLE_APPLICATION_CREDENTIALS):
        raise FileNotFoundError(f"Service account file not found: {env.GOOGLE_APPLICATION_CREDENTIALS}")

    env.SESH_PRO_BACKEND_DB_PATH  = os.getenv('SESH_PRO_BACKEND_DB_PATH', './backend.db')

    env.SESH_PRO_BACKEND_UNSAFE_LOGGING = os_get_boolean_env('SESH_PRO_BACKEND_UNSAFE_LOGGING', False)

    with OpenDBAtPath(env.SESH_PRO_BACKEND_DB_PATH) as db:
        backend.delete_user_errors(db.sql_conn, base.PaymentProvider.GooglePlayStore)

    with pubsub_v1.SubscriberClient() as sub_client:
        sub_path = sub_client.subscription_path(project='loki-5a81e', subscription='session-pro-sub')
        future = sub_client.subscribe(subscription=sub_path, callback=callback)
        future.result()

#entry_point()
