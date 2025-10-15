import json
import logging
import sqlite3
import threading
import dataclasses
import typing

from google.oauth2 import service_account
from google.cloud import pubsub_v1
import google.cloud.pubsub_v1.subscriber.message
import googleapiclient.discovery

import backend
import base
from backend import OpenDBAtPath, PaymentProviderTransaction, AddRevocationItem, UserErrorTransaction
from base import (
    ProPlan,
    JSONObject,
    json_dict_require_str,
    json_dict_require_str_coerce_to_int,
    safe_dump_dict_keys_or_data,
    json_dict_optional_obj,
    json_dict_require_int_coerce_to_enum,
    reflect_enum,
    obfuscate
)

import platform_google_api
from platform_google_api import SubscriptionPlanEventTransaction, VoidedPurchaseTxFields 
from platform_google_types import SubscriptionNotificationType, SubscriptionsV2SubscriptionAcknowledgementStateType, RefundType, ProductType, SubscriptionV2Data, SubscriptionsV2SubscriptionStateType

log = logging.Logger('GOOGLE')

@dataclasses.dataclass
class ThreadContext:
    thread:      threading.Thread | None = None
    kill_thread: bool                    = False

def _update_payment_renewal_info(tx_payment: PaymentProviderTransaction, auto_renewing: bool | None, grace_period_duration_ms: int | None, sql_conn: sqlite3.Connection, err: base.ErrorSink)-> bool:
    assert len(tx_payment.google_payment_token) > 0 and len(tx_payment.google_order_id) > 0 and not err.has()
    return backend.update_payment_renewal_info(
        sql_conn                 = sql_conn,
        payment_tx               = tx_payment,
        grace_period_duration_ms = grace_period_duration_ms,
        auto_renewing            = auto_renewing,
        err                      = err,
    )

def toggle_payment_auto_renew(tx_payment: PaymentProviderTransaction, auto_renewing: bool, sql_conn: sqlite3.Connection, err: base.ErrorSink):
    success = _update_payment_renewal_info(tx_payment, auto_renewing, None, sql_conn, err)
    if not success:
        err.msg_list.append(f'Failed to update auto_renew flag for purchase_token: {obfuscate(tx_payment.google_payment_token)} and order_id: {obfuscate(tx_payment.google_order_id)}')

def set_purchase_grace_period_duration(tx_payment: PaymentProviderTransaction, grace_period_duration_ms: int, sql_conn: sqlite3.Connection, err: base.ErrorSink):
    success = _update_payment_renewal_info(tx_payment, None, grace_period_duration_ms, sql_conn, err)
    if not success:
        err.msg_list.append(f'Failed to update grace period duration for purchase_token: {obfuscate(tx_payment.google_payment_token)} and order_id: {obfuscate(tx_payment.google_order_id)}')

# TODO: If this function ever finds rounded(expiry_ts) > rounded(event_ts) the devs need to be notified somehow.
def add_user_revocation_if_not_self_expiring(tx_payment: PaymentProviderTransaction, tx_event: SubscriptionPlanEventTransaction, tx: base.SQLTransaction, err: base.ErrorSink):
    """If everything works as intended, this function should always find that `rounded(expiry_ts) == rounded(event_ts)` and 
    not issue a revocation. If a payment is ever in a state where it should self-expire but isn't, we need to revoke it. In
    this case something has gone wrong and the user was over-entitled.
    """
    payment = backend.get_payment_tx(tx=tx, payment_tx=tx_payment, err=err)
    if payment is None or err.has():
        err.msg_list.append(f"Failed to get payment details for potential revocation!")
        return

    rounded_expiry_ts_ms = backend.round_unix_ts_ms_to_next_day_with_platform_testing_support(payment_provider=tx_payment.provider, unix_ts_ms=payment.expiry_unix_ts_ms)
    rounded_event_ts_ms = backend.round_unix_ts_ms_to_next_day_with_platform_testing_support(payment_provider=tx_payment.provider, unix_ts_ms=tx_event.event_ts_ms)

    # TODO: Discuss this again. If we don't revoke a payment that hasn't been registered because of
    # this branch, then, a user can still activate the payment later and probably get into an
    # inconsistent state.

    # NOTE: expiry_unix_ts_ms in the db is not rounded, but the proof's themselves have an
    # expiry timestamp rounded to the end of the UTC day. So we only actually want to revoke
    # proofs that aren't going to self-expire by the end of the day.
    if rounded_expiry_ts_ms > rounded_event_ts_ms:
        _ = backend.add_google_revocation_tx(tx,
                                             tx_payment.google_payment_token,
                                             revoke_unix_ts_ms=tx_event.event_ts_ms,
                                             err=err)

def validate_no_existing_purchase_token_error(purchase_token:str, sql_conn: sqlite3.Connection, err: base.ErrorSink):
    result = backend.get_user_error(sql_conn=sql_conn, provider_id=purchase_token)
    if result.provider_id == purchase_token:
        err.msg_list.append(f"Received RTDN notification for already errored purchase token: {obfuscate(purchase_token)}")

def handle_subscription_notification(tx_payment: PaymentProviderTransaction, tx_event: SubscriptionPlanEventTransaction, sql_conn: sqlite3.Connection, err: base.ErrorSink):
    match tx_event.notification:
        case SubscriptionNotificationType.SUBSCRIPTION_RECOVERED | SubscriptionNotificationType.SUBSCRIPTION_RENEWED:
            assert tx_event.pro_plan != ProPlan.Nil, "Plan was parsed into a valid enum when extracting data from the notification, should not be nil here"
            assert len(tx_payment.google_order_id) > 0 and len(tx_payment.google_payment_token) > 0

            # TODO: this needs to be tested, this state happens when you have a successful payment while in grace or account hold, re-activating subscription. It's unclear if a renewed event also happens.
            if tx_event.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_ACTIVE:
                # TODO: we might need to reset the grace period here, will need to see how the grace recovery works with order ids.
                with base.SQLTransaction(sql_conn) as tx:
                    assert tx_event.pro_plan != ProPlan.Nil, "Plan was parsed into a valid enum when extracting data from the notification, should not be nil here"
                    assert len(tx_payment.google_order_id) > 0 and len(tx_payment.google_payment_token) > 0
                    backend.add_unredeemed_payment_tx(
                        tx                                = tx,
                        payment_tx                        = tx_payment,
                        plan                              = tx_event.pro_plan,
                        expiry_unix_ts_ms                 = tx_event.expiry_time.unix_milliseconds,
                        unredeemed_unix_ts_ms             = tx_event.event_ts_ms,
                        platform_refund_expiry_unix_ts_ms = tx_event.event_ts_ms + platform_google_api.refund_deadline_duration_ms,
                        err                               = err)

        case SubscriptionNotificationType.SUBSCRIPTION_CANCELED:
            """Google mentions a case where if a user is on account hold and the canceled event happens they should have entitlement revoked, but entitlement is already expired so this does not need to be handled."""
            if tx_event.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_CANCELED or tx_event.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_EXPIRED:
                toggle_payment_auto_renew(tx_payment=tx_payment, auto_renewing=False, sql_conn=sql_conn, err=err)

        case SubscriptionNotificationType.SUBSCRIPTION_PURCHASED:
            """
            These are the steps documented by Google:
            When a user purchases a subscription, a SubscriptionNotification message with type SUBSCRIPTION_PURCHASED is sent to your RTDN client. Whether you receive this notification or you register a new purchase in-app through PurchasesUpdatedListener or manually fetching purchases in your app's onResume() method, you should process the new purchase in your secure backend. To do this, follow these steps:
            1. Query the purchases.subscriptionsv2.get endpoint to get a subscription resource that contains the latest subscription state.
            2. Make sure that the value of the subscriptionState field is SUBSCRIPTION_STATE_ACTIVE.
            3. Verify the purchase.
            4. Give the user access to the content. The user account associated with the purchase can be identified with the ExternalAccountIdentifiers object from the subscription resource if identifiers were set at purchase time using setObfuscatedAccountId and setObfuscatedProfileId.
            """

            if tx_event.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_ACTIVE:
                if tx_event.purchase_acknowledged == SubscriptionsV2SubscriptionAcknowledgementStateType.ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED:
                    err.msg_list.append(f'Latest subscription state is already acknowledged')
                else:
                    # NOTE: Acknowledge the payment
                    assert tx_event.pro_plan != ProPlan.Nil, "Plan was parsed into a valid enum when extracting data from the notification, should not be nil here"
                    assert len(tx_payment.google_order_id) > 0 and len(tx_payment.google_payment_token) > 0

                    with base.SQLTransaction(sql_conn) as tx:
                        # NOTE: If a linked token is in the payload, it means that the old token
                        # needs to be voided first before continuing as the link token is the new
                        # token allocated to the user.

                        # NOTE: Revoke the old token
                        if tx_event.linked_purchase_token is not None:
                            # NOTE: For google, the only information we have about the previous order
                            # is the purchase token. So we have to go and find the latest payment
                            # valid for a purchase token and void that.
                            _ = backend.add_google_revocation_tx(tx,
                                                                 tx_event.linked_purchase_token,
                                                                 revoke_unix_ts_ms=tx_event.event_ts_ms,
                                                                 err=err)
                        # NOTE: Register the payment
                        backend.add_unredeemed_payment_tx(
                            tx                                = tx,
                            payment_tx                        = tx_payment,
                            plan                              = tx_event.pro_plan,
                            expiry_unix_ts_ms                 = tx_event.expiry_time.unix_milliseconds,
                            unredeemed_unix_ts_ms             = tx_event.event_ts_ms,
                            platform_refund_expiry_unix_ts_ms = tx_event.event_ts_ms + platform_google_api.refund_deadline_duration_ms,
                            err                               = err,
                        )

                        # NOTE: On error rollback changes made to the DB
                        tx.cancel = err.has()

                        if not err.has():
                           platform_google_api.subscription_v1_acknowledge(purchase_token=tx_payment.google_payment_token, err=err)

        case SubscriptionNotificationType.SUBSCRIPTION_ON_HOLD:
            if tx_event.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_ON_HOLD:
                """
                The revocation function only actually revokes proofs that are not going to self-expire at the end of the UTC day, so
                for the vast majority of users this function wont make any changes to user entitlement. An example of when a proof will
                actually be revoked if the user enters account hold and for some reason their pro proof expires some time in the future
                (later than the end of the UTC day). A user enters account hold if their billing method is still failing after their
                grace period ends.
                """
                with base.SQLTransaction(sql_conn) as tx:
                    add_user_revocation_if_not_self_expiring(tx_payment=tx_payment, tx_event=tx_event, tx=tx, err=err)

        case SubscriptionNotificationType.SUBSCRIPTION_IN_GRACE_PERIOD:
            if tx_event.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_IN_GRACE_PERIOD:
                plan_details = platform_google_api.fetch_subscription_details_for_base_plan_id(base_plan_id=tx_event.base_plan_id, err=err)
                if not err.has():
                    assert plan_details is not None
                    set_purchase_grace_period_duration(tx_payment=tx_payment,
                                                       grace_period_duration_ms=plan_details.grace_period.milliseconds,
                                                       sql_conn=sql_conn,
                                                       err=err)

        case SubscriptionNotificationType.SUBSCRIPTION_RESTARTED:
            # Only happens when going from CANCELLED to ACTIVE, this is called resubscribing, or re-enabling auto-renew
            if tx_event.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_ACTIVE:
                toggle_payment_auto_renew(tx_payment=tx_payment, auto_renewing=True, sql_conn=sql_conn, err=err)

        case SubscriptionNotificationType.SUBSCRIPTION_DEFERRED:
            err.msg_list.append(f'Subscription notificationType {reflect_enum(tx_event.notification)} is unsupported!')

        case SubscriptionNotificationType.SUBSCRIPTION_PAUSED:
            err.msg_list.append(f'Subscription notificationType {reflect_enum(tx_event.notification)} is unsupported!')

        case SubscriptionNotificationType.SUBSCRIPTION_PAUSE_SCHEDULE_CHANGED:
            err.msg_list.append(f'Subscription notificationType {reflect_enum(tx_event.notification)} is unsupported!')

        case SubscriptionNotificationType.SUBSCRIPTION_REVOKED:
            if tx_event.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_EXPIRED:
                with base.SQLTransaction(sql_conn) as tx:
                    _ = backend.add_google_revocation_tx(tx,
                                                         tx_payment.google_payment_token,
                                                         revoke_unix_ts_ms=tx_event.event_ts_ms,
                                                         err=err)

        case SubscriptionNotificationType.SUBSCRIPTION_EXPIRED:
            """The revocation function only actually revokes proofs that are not going to self-expire at the end of the UTC day, so
            for the vast majority of users this function wont make any changes to user entitlement."""
            if tx_event.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_EXPIRED:
                with base.SQLTransaction(sql_conn) as tx:
                    add_user_revocation_if_not_self_expiring(tx_payment=tx_payment, tx_event=tx_event, tx=tx, err=err)

        # NOTE: No-op cases
        case SubscriptionNotificationType.SUBSCRIPTION_PRICE_CHANGE_CONFIRMED:
            pass
        case SubscriptionNotificationType.SUBSCRIPTION_PRICE_CHANGE_UPDATED:
            pass
        case SubscriptionNotificationType.SUBSCRIPTION_PENDING_PURCHASE_CANCELED:
            pass
        case SubscriptionNotificationType.SUBSCRIPTION_PRICE_STEP_UP_CONSENT_UPDATED:
            pass

    if err.has():
        # Purchase token logging is included in the wrapper function
        err.msg_list.append(f'Failed to handle {reflect_enum(tx_event.notification)} for order_id {obfuscate(tx_payment.google_order_id) if len(tx_payment.google_order_id) > 0 else "N/A"}')
        return

def handle_voided_notification(tx: VoidedPurchaseTxFields, err: base.ErrorSink):
    match tx.product_type:
        case ProductType.PRODUCT_TYPE_SUBSCRIPTION:
            match tx.refund_type:
                case RefundType.REFUND_TYPE_FULL_REFUND:
                    # TODO: investigate if we need to implement anything here
                    pass
                case RefundType.REFUND_TYPE_QUANTITY_BASED_PARTIAL_REFUND:
                    err.msg_list.append(f'voided purchase refundType {reflect_enum(tx.refund_type)} is unsupported!')
                case _:
                    err.msg_list.append(f'voided purchase refundType is not valid: {reflect_enum(tx.refund_type)}')
        case ProductType.PRODUCT_TYPE_ONE_TIME:
            err.msg_list.append(f'voided purchase productType {reflect_enum(tx.product_type)} is unsupported!')

    if err.has():
        err.msg_list.append(f'Failed to handle {reflect_enum(tx.refund_type) if tx.refund_type is not None else "N/A"} order_id {obfuscate(tx.order_id) if len(tx.order_id) > 0 else "N/A"}')


def handle_notification(body: JSONObject, sql_conn: sqlite3.Connection, err: base.ErrorSink) -> UserErrorTransaction:
    result               = UserErrorTransaction()
    body_version         = json_dict_require_str(body, "version", err)
    package_name         = json_dict_require_str(body, "packageName", err)
    event_time_millis    = json_dict_require_str_coerce_to_int(body, "eventTimeMillis", err)
    assert body_version == "1.0" # TODO: Do we want any non debug mode behaviour around mismatched version?

    if package_name != platform_google_api.package_name:
        err.msg_list.append(f'{package_name} does not match google_package_name ({platform_google_api.package_name}) from the .INI file!')

    subscription                     = json_dict_optional_obj(body, "subscriptionNotification", err)
    one_time_product                 = json_dict_optional_obj(body, "oneTimeProductNotification", err)
    voided_purchase                  = json_dict_optional_obj(body, "voidedPurchaseNotification", err)
    test_obj                         = json_dict_optional_obj(body, "testNotification", err)

    is_subscription_notification     = subscription is not None
    is_one_time_product_notification = one_time_product is not None
    is_voided_notification           = voided_purchase is not None
    is_test_notification             = test_obj is not None

    unique_notif_keys = is_subscription_notification + is_one_time_product_notification + is_voided_notification + is_test_notification

    if unique_notif_keys == 0:
        err.msg_list.append(f'No subscription notification for {package_name} {safe_dump_dict_keys_or_data(body)}')
    elif unique_notif_keys > 1:
        err.msg_list.append(f'Multiple subscription notification for {package_name} {safe_dump_dict_keys_or_data(body)}')

    if err.has():
        return result

    if is_subscription_notification:
        purchase_token = json_dict_require_str(subscription, "purchaseToken", err)
        validate_no_existing_purchase_token_error(purchase_token, sql_conn, err)
        if err.has():
            return result

        result.google_payment_token    = purchase_token
        version                        = json_dict_require_str(subscription, "version",  err)
        subscription_notification_type = json_dict_require_int_coerce_to_enum(subscription, "notificationType", SubscriptionNotificationType, err)
        details                        = platform_google_api.fetch_subscription_v2_details(package_name, purchase_token, err)
        assert version == "1.0" # TODO: Do we want any non debug mode behaviour around mismatched version?
        if err.has():
            err.msg_list.append(f'Parsing subscriptionv2 response for purchase token {obfuscate(purchase_token)} failed')
            return result

        assert details is not None and isinstance(subscription_notification_type, SubscriptionNotificationType)
        tx_payment = platform_google_api.parse_subscription_purchase_tx(purchase_token=purchase_token, details=details, err=err)
        tx_event   = platform_google_api.parse_subscription_plan_event_tx(details, event_time_millis, subscription_notification_type, err=err)
        if err.has():
            err.msg_list.append(f'Parsing data from subscriptionv2 for purchase token {obfuscate(purchase_token)} failed')
            return result

        handle_subscription_notification(tx_payment=tx_payment, tx_event=tx_event, sql_conn=sql_conn, err=err)

    elif is_voided_notification:
        purchase_token = json_dict_require_str(voided_purchase, "purchaseToken", err)
        validate_no_existing_purchase_token_error(purchase_token, sql_conn, err)
        if err.has():
            return result

        result.google_payment_token = purchase_token

        order_id = json_dict_require_str(voided_purchase, "orderId", err)
        product_type = json_dict_require_int_coerce_to_enum(voided_purchase, "productType", ProductType, err)
        refund_type = json_dict_require_int_coerce_to_enum(voided_purchase, "refundType", RefundType, err)

        assert refund_type is not None and product_type is not None and len(purchase_token) > 0 and len(order_id) > 0 and \
        isinstance(product_type, ProductType) and isinstance(refund_type, RefundType)
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
        log.info(f'Test payload was: {safe_dump_dict_keys_or_data(body)}')

    return result

def callback(message: google.cloud.pubsub_v1.subscriber.message.Message):
    body: typing.Any = json.loads(message.data)  # pyright: ignore[reportAny]
    if not isinstance(body, dict):
        logging.error(f'ERROR: Payload was not JSON: {safe_dump_dict_keys_or_data(body)}\n')  # pyright: ignore[reportAny]
        return

    # NOTE: Process the notification
    err      = base.ErrorSink()
    error_tx = UserErrorTransaction()
    with OpenDBAtPath(db_path=base.DB_PATH, uri=base.DB_PATH_IS_URI) as db:
        body     = typing.cast(JSONObject, body)
        error_tx = handle_notification(body, db.sql_conn, err)

    # NOTE: Handle errors
    if err.has():
        # NOTE: Record the error under the payment token if possible
        if len(error_tx.google_payment_token):
            # TODO: this logic should probably be inside of handle_notification
            err.msg_list.append(f'Failed to process event for purchase token: {obfuscate(error_tx.google_payment_token)}')

            # NOTE: Record the error
            error_tx.provider = base.PaymentProvider.GooglePlayStore
            err_internal      = base.ErrorSink()
            with OpenDBAtPath(db_path=base.DB_PATH, uri=base.DB_PATH_IS_URI) as db:
                backend.add_user_error(sql_conn=db.sql_conn, error_tx=error_tx, err=err)
            err.msg_list.extend(err_internal.msg_list)

        # NOTE: Log the error
        err_msg = '\n'.join(err.msg_list)
        logging.error(f'{err_msg}\nPayload was: {safe_dump_dict_keys_or_data(body)}\n')  # pyright: ignore[reportAny]

    # NOTE: Acknowledge the notification
    if not err.has():
        message.ack()

def thread_entry_point(context: ThreadContext, app_credentials_path: str, project_name: str, subscription_name: str):
    # NOTE: Start pulling subscriber from Google endpoints with the streaming pull client
    # By default this starts a thread pool to handle the messages and blocks on the future
    while context.kill_thread == False:
        with pubsub_v1.SubscriberClient.from_service_account_file(app_credentials_path) as client:
            sub_path = client.subscription_path(project=project_name, subscription=subscription_name)
            future   = client.subscribe(subscription=sub_path, callback=callback)
            while context.kill_thread == False:
                try:
                    future.result(timeout=0.5)
                except TimeoutError:
                    pass

def init(sql_conn:                sqlite3.Connection,
         project_name:            str,
         package_name:            str,
         subscription_name:       str,
         subscription_product_id: str,
         app_credentials_path:    str | None) -> ThreadContext:
    # NOTE: Setup credentials global variable
    assert platform_google_api.credentials       is None and \
           platform_google_api.publisher_service is None and \
           len(platform_google_api.package_name) == 0, \
            "Initialise was called twice. Google uses callbacks with no way to pass in a per-callback context so it needs global variables"

    if app_credentials_path:
        platform_google_api.credentials = service_account.Credentials.from_service_account_file(app_credentials_path,  # pyright: ignore[reportUnknownMemberType]
                                                                                                scopes=['https://www.googleapis.com/auth/androidpublisher'])
        platform_google_api.publisher_service = googleapiclient.discovery.build('androidpublisher', 'v3', credentials=platform_google_api.credentials)

    platform_google_api.package_name            = package_name
    platform_google_api.subscription_product_id = subscription_product_id

    # NOTE: Flush errors
    backend.delete_user_errors(sql_conn, base.PaymentProvider.GooglePlayStore)

    # NOTE: Setup thread for caller to use
    result        = ThreadContext()
    result.thread = threading.Thread(target=thread_entry_point, args=(result, app_credentials_path, project_name, subscription_name))
    return result
