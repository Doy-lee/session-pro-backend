'''
Entry point for witnessing notifications from the Google Play store. This layer initiates an
asynchronous fetching operation from Google to monitor for new payments, parsing
it and process said payments into the database layer (backend.py)
'''

import json
import traceback
import logging
import sqlite3
import threading
import dataclasses
import typing
import time
import sys

from   google.oauth2 import service_account
from   google.cloud  import pubsub_v1
import google.cloud.pubsub_v1.subscriber.message
import googleapiclient.discovery

import backend
import base
from backend import OpenDBAtPath, PaymentProviderTransaction, UserError
from base import (
    ProPlan,
    JSONObject,
    json_dict_require_str,
    json_dict_require_str_coerce_to_int,
    safe_dump_dict_keys_or_data,
    json_dict_optional_obj,
    json_dict_require_int_coerce_to_enum,
    reflect_enum,
)

import platform_google_api
from platform_google_api import SubscriptionPlanEventTransaction, VoidedPurchaseTxFields 
from platform_google_types import SubscriptionNotificationType, SubscriptionsV2SubscriptionAcknowledgementStateType, RefundType, ProductType, SubscriptionsV2SubscriptionStateType, SubscriptionV2Data

log = logging.Logger('GOOGLE')

@dataclasses.dataclass
class ThreadContext:
    thread:      threading.Thread | None = None
    kill_thread: bool                    = False
    sleep_event: threading.Event         = threading.Event()

@dataclasses.dataclass
class GoogleHandleNotificationResult:
    purchase_token: str  = ""
    ack:            bool = False

@dataclasses.dataclass
class TimestampedData:
    event_unix_ts_ms:   int        = 0
    received_unix_ts_s: float        = 0
    body:               typing.Any = None

def init(project_name:            str,
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
        platform_google_api.publisher_service = googleapiclient.discovery.build('androidpublisher', 'v3', credentials=platform_google_api.credentials)  # pyright: ignore[reportUnknownMemberType]

    platform_google_api.package_name            = package_name
    platform_google_api.subscription_product_id = subscription_product_id

    # NOTE: Setup thread for caller to use
    result        = ThreadContext()
    result.thread = threading.Thread(target=thread_entry_point, args=(result, app_credentials_path, project_name, subscription_name))
    return result

def thread_entry_point(context: ThreadContext, app_credentials_path: str, project_name: str, subscription_name: str):
    while context.kill_thread == False:
        with pubsub_v1.SubscriberClient.from_service_account_file(app_credentials_path) as client:
            sub_path = client.subscription_path(project=project_name, subscription=subscription_name)
            # future   = client.subscribe(subscription=sub_path, callback=callback)  # pyright: ignore[reportUnknownMemberType]

            # NOTE: We have a little bit of a problem here in terms of ordering. Google
            # notifications for payments can come out of order and if we miss them, they can also be
            # replayed out of order. Unfortunately in our initial designs we intended events to be
            # processed in order, this is a natural tendency that seems to be ill-suited for
            # integrating with Google given these behaviours.
            #
            # In Google payment notifications do not set the ordering keys such that an order can be
            # enforced for the same user's event I have witnessed notifications coming out of order
            # in replays and out of order within the same batch of messages downloaded at a time. We
            # are forced to then sort by event timestamp after the fact with some reasonable buffer
            # which adds to latency but will produce the desired outcomes.
            #
            # What maybe the more natural way to approach this system was to build an idempotent
            # notification handling system with the following pattern:
            #
            #  - Getting a notification
            #  - Compare last event timestamp we processed for the purchase token, ignore if it's
            #    too old
            #  - Get subscription details for the notification
            #  - Create the row if it doesn't exist in the state that google says it should be in,
            #    or, if already exists- state transition it into the state that google says it
            #    should be and ignore any violations of invariants (the final state it ends up in
            #    should be valid though)
            #  - Repeat
            #
            # TODO: Idempotency would remove the hard requirement on having to witness events in
            # order since they recommend we always reconcile with the state stored on the play
            # store, this seems doable but needs a longer time budget.
            #
            # Example payload:
            #
            #   received_messages {
            #     ack_id: "HxknBUxeR..."
            #     message {
            #       data: "{\"version\":\"1.0\",\"packageName\":\"network.loki.messenger\",\"eventTimeMillis\":\"1762752016420\",...}"
            #       message_id: "17064522705211191"
            #       publish_time {
            #         seconds: 1762752016
            #         nanos: 631000000
            #       }
            #     }
            #   }

            # NOTE: How long after receiving an event do we want before executing it. The time
            # inbetween is reserved to allow the Google pub/sub client to pull more messages which
            # can potentially come out of order. Increasing this increases the latency of when
            # a event is finalised in the system!! Putting this too low might mean that we observe
            # events out of order!! The system is configured to halt processing of events if
            # a message received out of order transitions a subscription into an invalid state!
            #
            # 8 seconds is an eternity, yes, but I have witnessed events coming as late as 3-4
            # seconds, oh well.
            TIME_BEFORE_HANDLING_EVENT_S = 8

            # NOTE: How often to poll Google for events in seconds
            POLL_FREQUENCY_S = 2

            ordered_msg_list:     list[TimestampedData] = []
            last_event_processed: TimestampedData       = TimestampedData()
            while context.kill_thread == False:
                log.info("pulling")
                result = client.pull(subscription=sub_path,
                                     return_immediately=True,
                                     max_messages=64)

                now: float = time.time()
                if len(result.received_messages) > 0:
                    # NOTE: Generate the list of messages sorted by their event time stamp
                    err        = base.ErrorSink()
                    for index, it in enumerate(result.received_messages):
                        body:          typing.Any = json.loads(it.message.data)
                        event_time_ms: int        = base.json_dict_require_str_coerce_to_int(body, 'eventTimeMillis', err)
                        ordered_msg_list.append(TimestampedData(received_unix_ts_s=now, event_unix_ts_ms=event_time_ms, body=it.message))
                        log.info("received event")

                    # NOTE: Sort the events we've added
                    ordered_msg_list.sort(key=lambda it: it.event_unix_ts_ms)

                # NOTE: Process events
                index = 0
                while index < len(ordered_msg_list):
                    msg                   = ordered_msg_list[index]
                    time_since_received_s = now - msg.received_unix_ts_s
                    if time_since_received_s < TIME_BEFORE_HANDLING_EVENT_S:
                        break

                    if last_event_processed.event_unix_ts_ms > msg.event_unix_ts_ms:
                        log.warning(f'The last event we processed came after the next event we ' +
                                     'processed (poll_freq={POLL_FREQUENCY_S}s, delay_before_handling_event_s={TIME_BEFORE_HANDLING_EVENT_S}\n' +
                                     'Previous event was:\n{last_event_processed}\nCurrent event was\n:{msg}')

                    last_event_processed = msg
                    handled              = handle_sub_message(msg.body)
                    if not handled:
                        log.warning(f'Discarding event because handling of it failed (message will be re-notified by google) {msg}')
                        _ = ordered_msg_list.pop(index)
                        continue

                    index += 1

                # NOTE: Erase the processed events
                ordered_msg_list = ordered_msg_list[index:]
                log.info("sleeping")
                _ = context.sleep_event.wait(POLL_FREQUENCY_S)

def _update_payment_renewal_info(tx_payment: PaymentProviderTransaction, auto_renewing: bool | None, grace_period_duration_ms: int | None, sql_conn: sqlite3.Connection, err: base.ErrorSink)-> bool:
    assert len(tx_payment.google_payment_token) > 0 and len(tx_payment.google_order_id) > 0 and not err.has()
    return backend.update_payment_renewal_info(
        sql_conn                 = sql_conn,
        payment_tx               = tx_payment,
        grace_period_duration_ms = grace_period_duration_ms,
        auto_renewing            = auto_renewing,
        err                      = err,
    )

def set_payment_auto_renew(tx_payment: PaymentProviderTransaction, auto_renewing: bool, sql_conn: sqlite3.Connection, err: base.ErrorSink):
    success = _update_payment_renewal_info(tx_payment, auto_renewing, None, sql_conn, err)
    if not success:
        err.msg_list.append(f'Failed to update auto_renew flag for purchase_token: {tx_payment.google_payment_token} and order_id: {tx_payment.google_order_id}')

def set_purchase_grace_period_duration(tx_payment: PaymentProviderTransaction, grace_period_duration_ms: int, sql_conn: sqlite3.Connection, err: base.ErrorSink):
    success = _update_payment_renewal_info(tx_payment, None, grace_period_duration_ms, sql_conn, err)
    if not success:
        err.msg_list.append(f'Failed to update grace period duration for purchase_token: {tx_payment.google_payment_token} and order_id: {tx_payment.google_order_id}')

def validate_no_existing_purchase_token_error(purchase_token: str, sql_conn: sqlite3.Connection, err: base.ErrorSink):
    result = backend.has_user_error(sql_conn=sql_conn, payment_provider=base.PaymentProvider.GooglePlayStore, payment_id=purchase_token)
    if result:
        err.msg_list.append(f"Received RTDN notification for already errored purchase token: {purchase_token}")

def handle_subscription_notification(tx_payment: PaymentProviderTransaction, tx_event: SubscriptionPlanEventTransaction, sql_conn: sqlite3.Connection, err: base.ErrorSink): 
    match tx_event.notification:
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

                    if log.getEffectiveLevel() <= logging.INFO:
                        expiry:        str = base.readable_unix_ts_ms(tx_event.expiry_time.unix_milliseconds)
                        unredeemed:    str = base.readable_unix_ts_ms(tx_event.event_ts_ms)
                        payment_label: str = backend.payment_provider_tx_log_label(tx_payment)
                        log.info(f'{tx_event.notification.name}+{tx_event.subscription_state.name}; (linked_token={tx_event.linked_purchase_token}, plan={tx_event.pro_plan.name}, payment={payment_label}, unredeemed={unredeemed}, expiry={expiry})')

                    with base.SQLTransaction(sql_conn) as tx:
                        # NOTE: If a linked token is in the payload, it means that the old token
                        # needs to be voided first before continuing as the link token is the new
                        # token allocated to the user.

                        # NOTE: Revoke the old token
                        if tx_event.linked_purchase_token is not None:
                            # NOTE: For google, the only information we have about the previous order
                            # is the purchase token. So we have to go and find the latest payment
                            # valid for a purchase token and void that.
                            _ = backend.add_google_revocation_tx(tx                   = tx,
                                                                 google_payment_token = tx_event.linked_purchase_token,
                                                                 revoke_unix_ts_ms    = tx_event.event_ts_ms,
                                                                 err                  = err)
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

                        if not err.has():
                            platform_google_api.subscription_v1_acknowledge(purchase_token=tx_payment.google_payment_token, err=err)

                        # NOTE: On error rollback changes made to the DB
                        tx.cancel = err.has()

        case SubscriptionNotificationType.SUBSCRIPTION_IN_GRACE_PERIOD:
            if tx_event.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_IN_GRACE_PERIOD:
                plan_details = platform_google_api.fetch_subscription_details_for_base_plan_id(base_plan_id=tx_event.base_plan_id, err=err)

                if log.getEffectiveLevel() <= logging.INFO:
                    payment_label = backend.payment_provider_tx_log_label(tx_payment)
                    grace_ms: int = plan_details.grace_period.milliseconds if plan_details else 0
                    log.info(f'{tx_event.notification.name}+{tx_event.subscription_state.name}; (payment={payment_label}, grace period ms={grace_ms})')

                if not err.has():
                    assert plan_details is not None
                    set_purchase_grace_period_duration(tx_payment               = tx_payment,
                                                       grace_period_duration_ms = plan_details.grace_period.milliseconds,
                                                       sql_conn                 = sql_conn,
                                                       err                      = err)

        case SubscriptionNotificationType.SUBSCRIPTION_RECOVERED | SubscriptionNotificationType.SUBSCRIPTION_RENEWED:
            if tx_event.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_ACTIVE:

                if log.getEffectiveLevel() <= logging.INFO:
                    expiry        = base.readable_unix_ts_ms(tx_event.expiry_time.unix_milliseconds)
                    unredeemed    = base.readable_unix_ts_ms(tx_event.event_ts_ms)
                    payment_label = backend.payment_provider_tx_log_label(tx_payment)
                    log.info(f'{tx_event.notification.name}+{tx_event.subscription_state.name}; (payment={payment_label}, plan={tx_event.pro_plan.name}, unredeemed={unredeemed}, expiry={expiry})')

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
            if tx_event.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_CANCELED \
            or tx_event.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_EXPIRED:
                if log.getEffectiveLevel() <= logging.INFO:
                    payment_label = backend.payment_provider_tx_log_label(tx_payment)
                    log.info(f'{tx_event.notification.name}+{tx_event.subscription_state.name}; (payment={payment_label}, auto_renew=false)')
                set_payment_auto_renew(tx_payment=tx_payment, auto_renewing=False, sql_conn=sql_conn, err=err)

        case SubscriptionNotificationType.SUBSCRIPTION_RESTARTED:
            # Only happens when going from CANCELLED to ACTIVE, this is called resubscribing, or re-enabling auto-renew
            if tx_event.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_ACTIVE:
                if log.getEffectiveLevel() <= logging.INFO:
                    payment_label = backend.payment_provider_tx_log_label(tx_payment)
                    log.info(f'{tx_event.notification.name}+{tx_event.subscription_state.name}; (payment={payment_label}, auto_renew=true)')
                set_payment_auto_renew(tx_payment=tx_payment, auto_renewing=True, sql_conn=sql_conn, err=err)

        case SubscriptionNotificationType.SUBSCRIPTION_REVOKED:
            if tx_event.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_EXPIRED:
                if log.getEffectiveLevel() <= logging.INFO:
                    payment_label = backend.payment_provider_tx_log_label(tx_payment)
                    log.info(f'{tx_event.notification.name}+{tx_event.subscription_state.name}; (payment={payment_label}, auto_renew=false)')
                with base.SQLTransaction(sql_conn) as tx:
                    _ = backend.add_google_revocation_tx(tx                   = tx,
                                                         google_payment_token = tx_payment.google_payment_token,
                                                         revoke_unix_ts_ms    = tx_event.event_ts_ms,
                                                         err                  = err)

        case SubscriptionNotificationType.SUBSCRIPTION_EXPIRED | SubscriptionNotificationType.SUBSCRIPTION_ON_HOLD:
            """The revocation function only actually revokes proofs that are not going to self-expire at the end of the UTC day, so
            for the vast majority of users this function wont make any changes to user entitlement. An example of when a proof will
            actually be revoked if the user enters account hold and for some reason their pro proof expires some time in the future
            (later than the end of the UTC day). A user enters account hold if their billing method is still failing after their
            grace period ends.
            """
            if tx_event.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_EXPIRED \
            or tx_event.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_ON_HOLD:

                if log.getEffectiveLevel() <= logging.INFO:
                    payment_label = backend.payment_provider_tx_log_label(tx_payment)
                    log.info(f'{tx_event.notification.name}+{tx_event.subscription_state.name}; (payment={payment_label}, revoke={base.readable_unix_ts_ms(tx_event.event_ts_ms)})')

                with base.SQLTransaction(sql_conn) as tx:
                    # TODO: If this function ever finds rounded(expiry_ts) > rounded(event_ts) the devs need to be notified somehow.
                    """If everything works as intended, this function should always find that `rounded(expiry_ts) == rounded(event_ts)` and 
                    not issue a revocation. If a payment is ever in a state where it should self-expire but isn't, we need to revoke it. In
                    this case something has gone wrong and the user was over-entitled.
                    """
                    payment: backend.PaymentRow | None = backend.get_payment_tx(tx=tx, payment_tx=tx_payment, err=err)
                    if payment is None or err.has():
                        err.msg_list.append(f"Failed to get payment details for potential revocation!")

                    if not err.has():
                        assert payment is not None
                        rounded_expiry_ts_ms = backend.round_unix_ts_ms_to_next_day_with_platform_testing_support(payment_provider=tx_payment.provider, unix_ts_ms=payment.expiry_unix_ts_ms)
                        rounded_event_ts_ms = backend.round_unix_ts_ms_to_next_day_with_platform_testing_support(payment_provider=tx_payment.provider, unix_ts_ms=tx_event.event_ts_ms)

                        # NOTE: expiry_unix_ts_ms in the db is not rounded, but the proof's themselves have an
                        # expiry timestamp rounded to the end of the UTC day. So we only actually want to revoke
                        # proofs that aren't going to self-expire by the end of the day.
                        if rounded_expiry_ts_ms > rounded_event_ts_ms:
                            _ = backend.add_google_revocation_tx(tx                   = tx,
                                                                 google_payment_token = tx_payment.google_payment_token,
                                                                 revoke_unix_ts_ms    = tx_event.event_ts_ms,
                                                                 err                  = err)

        # NOTE: Explicitly unsupported cases
        case SubscriptionNotificationType.SUBSCRIPTION_DEFERRED |\
            SubscriptionNotificationType.SUBSCRIPTION_PAUSED |\
            SubscriptionNotificationType.SUBSCRIPTION_PAUSE_SCHEDULE_CHANGED:
            err.msg_list.append(f'Subscription notificationType {reflect_enum(tx_event.notification)} is unsupported!')

        # NOTE: No-op cases
        case SubscriptionNotificationType.SUBSCRIPTION_PRICE_CHANGE_CONFIRMED |\
             SubscriptionNotificationType.SUBSCRIPTION_PRICE_CHANGE_UPDATED |\
             SubscriptionNotificationType.SUBSCRIPTION_PENDING_PURCHASE_CANCELED |\
             SubscriptionNotificationType.SUBSCRIPTION_PRICE_STEP_UP_CONSENT_UPDATED:
            pass

    if err.has():
        # Purchase token logging is included in the wrapper function
        err.msg_list.append(f'Failed to handle {reflect_enum(tx_event.notification)} for order_id {tx_payment.google_order_id if len(tx_payment.google_order_id) > 0 else "N/A"}')

def handle_voided_notification(tx: VoidedPurchaseTxFields, err: base.ErrorSink):
    match tx.product_type:
        case ProductType.PRODUCT_TYPE_SUBSCRIPTION:
            match tx.refund_type:
                case RefundType.REFUND_TYPE_FULL_REFUND:
                    # TODO: investigate if we need to implement anything here
                    pass
                case RefundType.REFUND_TYPE_QUANTITY_BASED_PARTIAL_REFUND:
                    err.msg_list.append(f'voided purchase refundType {reflect_enum(tx.refund_type)} is unsupported!')
        case ProductType.PRODUCT_TYPE_ONE_TIME:
            err.msg_list.append(f'voided purchase productType {reflect_enum(tx.product_type)} is unsupported!')

    if err.has():
        err.msg_list.append(f'Failed to handle {reflect_enum(tx.refund_type)}')


def handle_notification(body: JSONObject, sql_conn: sqlite3.Connection, err: base.ErrorSink) -> GoogleHandleNotificationResult:
    result               = GoogleHandleNotificationResult()
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
        result.purchase_token = json_dict_require_str(subscription, "purchaseToken", err)
        if err.has():
            return result

        try:
            validate_no_existing_purchase_token_error(result.purchase_token, sql_conn, err)
            if err.has():
                return result

            version                        = json_dict_require_str(subscription, "version",  err)
            subscription_notification_type = json_dict_require_int_coerce_to_enum(subscription, "notificationType", SubscriptionNotificationType, err)
            details                        = platform_google_api.fetch_subscription_v2_details(package_name, result.purchase_token, err)
            assert version == "1.0" # TODO: Do we want any non debug mode behaviour around mismatched version?
            if err.has():
                err.msg_list.append(f'Parsing subscriptionv2 response failed')
                return result

            assert details is not None and isinstance(subscription_notification_type, SubscriptionNotificationType)
            tx_payment = platform_google_api.parse_subscription_purchase_tx(purchase_token=result.purchase_token, details=details, err=err)
            tx_event   = platform_google_api.parse_subscription_plan_event_tx(details, event_time_millis, subscription_notification_type, err=err)
            if err.has():
                err.msg_list.append(f'Parsing data from subscriptionv2 failed')
                return result

            handle_subscription_notification(tx_payment=tx_payment, tx_event=tx_event, sql_conn=sql_conn, err=err)
            result.ack = not err.has()
        except Exception:
            err.msg_list.append(f"Handling notification failed: {traceback.format_exc()}")

    elif is_voided_notification:
        result.purchase_token = json_dict_require_str(voided_purchase, "purchaseToken", err)
        if err.has():
            return result

        try:
            validate_no_existing_purchase_token_error(result.purchase_token, sql_conn, err)
            if err.has():
                return result

            order_id        = json_dict_require_str(voided_purchase, "orderId", err)
            product_type    = json_dict_require_int_coerce_to_enum(voided_purchase, "productType", ProductType, err)
            refund_type     = json_dict_require_int_coerce_to_enum(voided_purchase, "refundType", RefundType, err)
            if err.has():
                err.msg_list.append(f'Parsing data from subscriptionv2 failed')
                return result

            assert refund_type is not None and product_type is not None and len(result.purchase_token) > 0 and \
            len(order_id) > 0 and isinstance(product_type, ProductType) and isinstance(refund_type, RefundType)
            tx = VoidedPurchaseTxFields(
                purchase_token=result.purchase_token,
                order_id=order_id,
                event_ts_ms=event_time_millis,
                product_type=product_type,
                refund_type=refund_type,
            )
            handle_voided_notification(tx, err)
            result.ack = not err.has()
        except Exception:
            err.msg_list.append("Handling notification failed: {traceback.format_exc()}")

    elif is_one_time_product_notification:
        err.msg_list.append(f'one time product is not supported!')

    elif is_test_notification:
        log.info(f'Test payload was: {safe_dump_dict_keys_or_data(body)}')
        result.ack = True

    return result

def handle_sub_message(message: google.cloud.pubsub_v1.subscriber.message.Message) -> bool:
    result = False
    body: typing.Any = json.loads(message.data)  # pyright: ignore[reportAny]
    if not isinstance(body, dict):
        logging.error(f'Payload was not JSON: {safe_dump_dict_keys_or_data(body)}\n')  # pyright: ignore[reportAny]
        return result

    # NOTE: Process the notification
    err    = base.ErrorSink()
    notif_result = GoogleHandleNotificationResult()
    with OpenDBAtPath(db_path=base.DB_PATH, uri=base.DB_PATH_IS_URI) as db:
        body   = typing.cast(JSONObject, body)
        notif_result = handle_notification(body, db.sql_conn, err)

    if not notif_result.ack and not err.has():
        err.msg_list.append("Notification wasnt marked to be acknowledged but contained no errors! What happened?")

    # NOTE: Record the error under the payment token if possible to propagate to clients
    if err.has() and len(notif_result.purchase_token):
        err.msg_list.append(f'Failed to process event for purchase token: {notif_result.purchase_token}')

        # NOTE: Record the error
        user_error = UserError(
            provider             = base.PaymentProvider.GooglePlayStore,
            google_payment_token = notif_result.purchase_token,
        )
        with OpenDBAtPath(db_path=base.DB_PATH, uri=base.DB_PATH_IS_URI) as db:
            backend.add_user_error(sql_conn=db.sql_conn, error=user_error, unix_ts_ms=int(time.time() * 1000))

    if err.has():
        # NOTE: Log the error
        err_msg = '\n'.join(err.msg_list)
        logging.error(f'{err_msg}\nPayload was: {safe_dump_dict_keys_or_data(body)}\n')  # pyright: ignore[reportAny]
        result = False
    elif notif_result.ack:
        # NOTE: Acknowledge the notification
        message.ack()
        result = True

    return result
