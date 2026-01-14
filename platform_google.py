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
import enum
import collections.abc

from   google.oauth2 import service_account
from   google.cloud  import pubsub_v1
import google.pubsub_v1.types
import googleapiclient.discovery
import google.api_core.exceptions

import backend
import base
from backend import OpenDBAtPath, UserError
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
from platform_google_types import SubscriptionNotificationType, SubscriptionsV2AcknowledgementState, RefundType, ProductType, SubscriptionsV2State, SubscriptionV2Data

log = logging.Logger('GOOGLE')

@dataclasses.dataclass
class ThreadContext:
    thread:      threading.Thread | None = None
    kill_thread: bool                    = False
    sleep_event: threading.Event         = threading.Event()

class ParsedNotificationPayloadType(enum.Enum):
    Nil            = 0
    Subscription   = 1
    Voided         = 2
    Test           = 3
    OneTimeProduct = 4

@dataclasses.dataclass
class ParsedNotification:
    payload_type:    ParsedNotificationPayloadType = ParsedNotificationPayloadType.Nil
    payload_version: str                           = ''
    sub_type:        SubscriptionNotificationType  = SubscriptionNotificationType.NIL
    voided:          VoidedPurchaseTxFields        = dataclasses.field(default_factory=VoidedPurchaseTxFields)
    body_version:    str                           = ''
    event_time_ms:   int                           = 0
    package_name:    str                           = ''
    purchase_token:  str                           = ''

@dataclasses.dataclass
class SortedMessage:
    event_unix_ts_ms:     int                                           = 0
    next_retry_unix_ts_s: float                                         = 0
    curr_retry_delay_s:   float                                         = 0
    message_id:           int                                           = 0
    ack_id:               str                                           = ''
    parse:                ParsedNotification                            = dataclasses.field(default_factory=ParsedNotification)
    raw:                  google.pubsub_v1.types.ReceivedMessage | None = None

    def increase_retry_delay(self, now_s: float):
        MIN_RETRY_DELAY_S: float = 1
        MAX_RETRY_DELAY_S: float = 600
        self.curr_retry_delay_s    = max(self.curr_retry_delay_s, MIN_RETRY_DELAY_S)
        self.curr_retry_delay_s   *= 2
        self.curr_retry_delay_s    = min(self.curr_retry_delay_s, MAX_RETRY_DELAY_S)
        self.next_retry_unix_ts_s  = now_s + self.curr_retry_delay_s

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

def handle_parsed_notification(tx: base.SQLTransaction, parse: ParsedNotification, err: base.ErrorSink) -> bool:
    result = False
    match parse.payload_type:
        case ParsedNotificationPayloadType.Nil:
            pass

        case ParsedNotificationPayloadType.Subscription:
            try:
                details: SubscriptionV2Data | None = platform_google_api.fetch_subscription_v2_details(parse.package_name, parse.purchase_token, err)
                if err.has():
                    err.msg_list.append(f'Failed to fetch subscription V2 details from Google')
                    return result

                assert details is not None
                tx_payment = platform_google_api.parse_subscription_purchase_tx(purchase_token=parse.purchase_token, details=details, err=err)
                tx_event   = platform_google_api.parse_subscription_plan_event_tx(details, parse.event_time_ms, parse.sub_type, err=err)
                if err.has():
                    err.msg_list.append(f'Parsing data from subscription V2 details failed')
                    return result

                handle_subscription_notification(tx_payment=tx_payment, tx_event=tx_event, tx=tx, err=err)
            except Exception:
                err.msg_list.append(f"Handling notification failed: {traceback.format_exc()}")
        case ParsedNotificationPayloadType.Voided:
            try:
                handle_voided_notification(parse.voided, err)
            except Exception:
                err.msg_list.append("Handling notification failed: {traceback.format_exc()}")

        case ParsedNotificationPayloadType.OneTimeProduct:
            err.msg_list.append(f'One time product is not supported!')

        case ParsedNotificationPayloadType.Test:
            pass

    result = not err.has()
    if err.has():
        assert tx.cancel == True
    return result

def thread_entry_point(context: ThreadContext, app_credentials_path: str, project_name: str, subscription_name: str):
    sorted_msg_list: list[SortedMessage] = []

    # NOTE Load unhandled messages from the DB and insert it in to the list of messages to start off
    with OpenDBAtPath(db_path=base.DB_PATH, uri=base.DB_PATH_IS_URI) as db:
        with base.SQLTransaction(db.sql_conn) as tx:
            db_it: collections.abc.Iterator[backend.GoogleUnhandledNotificationIterator] = backend.google_get_unhandled_notification_iterator(tx)
            for row in db_it:
                message_id          = row[0]
                payload: str | None = row[1]
                if not payload:
                    continue

                raw_msg      = typing.cast(google.pubsub_v1.types.ReceivedMessage, google.pubsub_v1.types.ReceivedMessage.from_json(payload))
                message_data = json.loads(raw_msg.message.data)
                tmp_err      = base.ErrorSink()
                parse        = parse_notification(message_data, tmp_err);

                sorted_msg_list.append(SortedMessage(event_unix_ts_ms   = parse.event_time_ms,
                                                     message_id         = message_id,
                                                     parse              = parse,
                                                     ack_id             = raw_msg.ack_id,
                                                     raw                = raw_msg))

    # NOTE: Then connect to Google and start pulling messages
    log.info(f'Loaded {len(sorted_msg_list)} unhandled messages from the DB')
    while context.kill_thread == False:
        with pubsub_v1.SubscriberClient.from_service_account_file(app_credentials_path) as client:
            sub_path = client.subscription_path(project=project_name, subscription=subscription_name)
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
            # Example payload:
            #
            #   received_messages [{
            #     ack_id: "HxknBUxeR..."
            #     message {
            #       data: "{\"version\":\"1.0\",\"packageName\":\"network.loki.messenger\",\"eventTimeMillis\":\"1762752016420\",...}"
            #       message_id: "17064522705211191"
            #       publish_time {
            #         seconds: 1762752016
            #         nanos: 631000000
            #       }
            #     }
            #   }, ...]
            while context.kill_thread == False:
                try:
                    # NOTE: Pull messages from Google
                    result: google.pubsub_v1.types.PullResponse = client.pull(subscription       = sub_path,  # pyright: ignore[reportUnknownMemberType]
                                                                              return_immediately = False,
                                                                              max_messages       = 64)

                    # NOTE: Parse the received_messages[].message.data into our queue of messages
                    now:     float = time.time()
                    ack_ids: list[str] = []
                    for index, it in enumerate(result.received_messages):
                        err                              = base.ErrorSink()
                        message_data: base.JSONObject    = json.loads(it.message.data)  # pyright: ignore[reportAny]
                        parse:        ParsedNotification = parse_notification(message_data, err);
                        message_id:   int                = int(it.message.message_id)
                        if err.has():
                            log.warning(f'Discarding message #{index} because we encountered an error parsing it (message was published at {base.readable_unix_ts_ms(it.message.publish_time.ToMilliseconds())}. Message was:\n{it}\nReason was:\n{err.build()}')
                        else:
                            is_new_message = True
                            for sort_it in sorted_msg_list:
                                if sort_it.message_id == message_id:
                                    is_new_message = False
                                    break;

                            # NOTE: Try add it to the DB first, if this fails then we will not add
                            # it to the sorted message list otherwise our code to check that
                            # notification is handled or not is going to be bypassed and cause state
                            # inconsistencies.
                            def add_notification_id_to_db():
                                with OpenDBAtPath(db_path=base.DB_PATH, uri=base.DB_PATH_IS_URI) as db:
                                    with base.SQLTransaction(db.sql_conn) as tx:
                                        if backend.google_notification_message_id_is_in_db_tx(tx, message_id).present == False:
                                            # NOTE: Our message retention policy for this subscription is 7 days
                                            # (default). We add a little buffer as we don't know exactly which
                                            # timestamp Google uses.
                                            #
                                            # We always store the messages to mitigate network failures on
                                            # acknowledgement. We store this in JSON because in the
                                            # erroneous case there's highly likelihood we need human
                                            # intervention and having human-readability there will be
                                            # important.
                                            backend.google_add_notification_id_tx(tx                = tx,
                                                                                  message_id        = message_id,
                                                                                  expiry_unix_ts_ms = parse.event_time_ms + base.MILLISECONDS_IN_DAY * 8,
                                                                                  payload           = google.pubsub_v1.types.ReceivedMessage.to_json(it))

                            base.retry_function_on_database_locked_error(add_notification_id_to_db, log, "Add Google notification ID to DB failed", err)
                            if err.has():
                                log.warning(f'Discarding message #{index}, attempting to add notification to DB but it repeatedly failed (message was published at {base.readable_unix_ts_ms(it.message.publish_time.ToMilliseconds())}. Message was:\n{it}\nReason was:\n{err.build()}')
                                continue

                            if is_new_message:
                                sorted_msg_list.append(SortedMessage(event_unix_ts_ms   = parse.event_time_ms,
                                                                     message_id         = message_id,
                                                                     parse              = parse,
                                                                     ack_id             = it.ack_id,
                                                                     raw                = it))

                    # NOTE: Sort the messages we've added
                    if len(result.received_messages):
                        sorted_msg_list.sort(key=lambda it: it.event_unix_ts_ms)

                    # NOTE: Attempt to process them in order
                    index = 0
                    while index < len(sorted_msg_list):
                        err                    = base.ErrorSink()
                        msg:     SortedMessage = sorted_msg_list[index]
                        attempt: bool          = now > msg.next_retry_unix_ts_s
                        handled: bool          = False

                        # NOTE: Attempt to process the message. Just before we execute it, we also check
                        # that it hasn't been handled in the DB already. It's possible that someone
                        # out-of-band executed the SET_GOOGLE_NOTIFICATION command via environment/.ini
                        # file to mark a message as being done or handled so we check before proceeding.
                        if attempt:
                            try:
                                with OpenDBAtPath(db_path=base.DB_PATH, uri=base.DB_PATH_IS_URI) as db:
                                    # NOTE: If we try to mutate the database and it's locked, unlike
                                    # before we just set the handled flag to false. This causes the
                                    # message to be reattempted. In the add notification ID to DB phase
                                    # we manually implement a retry to handle that.
                                    #
                                    # On any other error we raise the exception to the top-level handler
                                    # which will log it for us.
                                    lookup = backend.GoogleNotificationMessageIDInDB()
                                    with base.SQLTransaction(db.sql_conn) as tx:
                                        # NOTE: By definition to be in the sorted list, the message must
                                        # have also been submitted into the DB. So if for some reason the
                                        # notification doesn't exist anymore (maybe someone deleted it
                                        # out-of-band) then we skip the notification.
                                        lookup                 = backend.google_notification_message_id_is_in_db_tx(tx, msg.message_id)
                                        user_is_in_error_state = backend.has_user_error_tx(tx=tx, payment_provider=base.PaymentProvider.GooglePlayStore, payment_id=msg.parse.purchase_token)
                                        if not lookup.present or lookup.present and lookup.handled:
                                            handled = True
                                        else:
                                            handled = handle_parsed_notification(tx, msg.parse, err)

                                        # NOTE: Clear user error if success, or add one if we failed
                                        if lookup.present:
                                            if handled:
                                                _ = backend.google_set_notification_handled(tx=tx, message_id=msg.message_id, delete=False)
                                                if user_is_in_error_state:
                                                    _ = backend.delete_user_errors_tx(tx=tx, payment_provider=base.PaymentProvider.GooglePlayStore, payment_id=msg.parse.purchase_token)
                                            elif user_is_in_error_state == False:
                                                user_error                      = backend.UserError()
                                                user_error.provider             = base.PaymentProvider.GooglePlayStore
                                                user_error.google_payment_token = msg.parse.purchase_token
                                                backend.add_user_error_tx(tx, error = user_error, unix_ts_ms = int(now * 1000))
                            except Exception as e:
                                # NOTE: On exception failure we'll just mark the message as not
                                # handled, this will bump the retry delay of the message
                                handled = False

                        # NOTE: On success, we remove the message and add it to the acknowledge list
                        # (to stop Google resending it), or otherwise configure an exponential back-off
                        # on the retry and skip the message
                        if handled:
                            _ = sorted_msg_list.pop(index)
                            ack_ids.append(msg.ack_id)
                        else:
                            index += 1
                            if attempt:
                                # NOTE: Exponential backoff on retries. Hopefully, this gives us some time,
                                # for the out-of-order messages that this message is dependent on to arrive,
                                # get sorted into order and then executed successfully.
                                msg.increase_retry_delay(now)
                                log.error(f'Failed to handle message, retrying in {msg.curr_retry_delay_s}s (message was emitted at {base.readable_unix_ts_ms(msg.event_unix_ts_ms)}). Reason was\n{err.build()}\nMessage was\n{msg.raw}')

                    # NOTE: Acknowledge the messages we handled successfully to stop Google from
                    # resending it to us
                    if len(ack_ids):
                        try:
                            client.acknowledge(subscription=sub_path, ack_ids = ack_ids)  # pyright: ignore[reportUnknownMemberType]
                        except google.api_core.exceptions.InvalidArgument:
                            # NOTE: Ignore double-ack, especially if the notification we had was very
                            # old and we only got around to completing it now rather than when it was
                            # still ackable
                            #
                            #  InvalidArgument: 400 Some acknowledgement ids in the request were
                            # invalid. This could be because the acknowledgement ids have expired or the
                            # acknowledgement ids were malformed. [reason: "EXACTLY_ONCE_ACKID_FAILURE"
                            pass
                except Exception:
                    log.error(f'Google notification handling failed. Error was {traceback.format_exc()}')

def _update_payment_renewal_info(tx_payment: base.PaymentProviderTransaction, auto_renewing: bool | None, grace_period_duration_ms: int | None, tx: base.SQLTransaction, err: base.ErrorSink)-> bool:
    assert len(tx_payment.google_payment_token) > 0 and len(tx_payment.google_order_id) > 0 and not err.has()
    return backend.update_payment_renewal_info_tx(
        tx                       = tx,
        payment_tx               = tx_payment,
        grace_period_duration_ms = grace_period_duration_ms,
        auto_renewing            = auto_renewing,
        err                      = err,
    )

def set_payment_auto_renew(tx_payment: base.PaymentProviderTransaction, auto_renewing: bool, tx: base.SQLTransaction, err: base.ErrorSink):
    success = _update_payment_renewal_info(tx_payment, auto_renewing, None, tx, err)
    if not success:
        err.msg_list.append(f'Failed to update auto_renew flag for purchase_token: {tx_payment.google_payment_token} and order_id: {tx_payment.google_order_id}')

def set_purchase_grace_period_duration(tx_payment: base.PaymentProviderTransaction, grace_period_duration_ms: int, tx: base.SQLTransaction, err: base.ErrorSink):
    success = _update_payment_renewal_info(tx_payment, None, grace_period_duration_ms, tx, err)
    if not success:
        err.msg_list.append(f'Failed to update grace period duration for purchase_token: {tx_payment.google_payment_token} and order_id: {tx_payment.google_order_id}')

def validate_no_existing_purchase_token_error(purchase_token: str, sql_conn: sqlite3.Connection, err: base.ErrorSink):
    result = backend.has_user_error(sql_conn=sql_conn, payment_provider=base.PaymentProvider.GooglePlayStore, payment_id=purchase_token)
    if result:
        err.msg_list.append(f"Received RTDN notification for already errored purchase token: {purchase_token}")

def handle_subscription_notification(tx_payment: base.PaymentProviderTransaction, tx_event: SubscriptionPlanEventTransaction, tx: base.SQLTransaction, err: base.ErrorSink):
    match tx_event.notification:
        case SubscriptionNotificationType.PURCHASED:
            """
            These are the steps documented by Google:
            When a user purchases a subscription, a SubscriptionNotification message with type SUBSCRIPTION_PURCHASED is sent to your RTDN client. Whether you receive this notification or you register a new purchase in-app through PurchasesUpdatedListener or manually fetching purchases in your app's onResume() method, you should process the new purchase in your secure backend. To do this, follow these steps:
            1. Query the purchases.subscriptionsv2.get endpoint to get a subscription resource that contains the latest subscription state.
            2. Make sure that the value of the subscriptionState field is SUBSCRIPTION_STATE_ACTIVE.
            3. Verify the purchase.
            4. Give the user access to the content. The user account associated with the purchase can be identified with the ExternalAccountIdentifiers object from the subscription resource if identifiers were set at purchase time using setObfuscatedAccountId and setObfuscatedProfileId.
            """
            if tx_event.subscription_state == SubscriptionsV2State.ACTIVE:
                if tx_event.purchase_acknowledged == SubscriptionsV2AcknowledgementState.ACKNOWLEDGED:
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
                        set_purchase_grace_period_duration(tx_payment               = tx_payment,
                                                           tx                       = tx,
                                                           grace_period_duration_ms = base.DEFAULT_GRACE_PERIOD_DURATION_MS,
                                                           err                      = err)

        case SubscriptionNotificationType.IN_GRACE_PERIOD:
            if tx_event.subscription_state == SubscriptionsV2State.IN_GRACE_PERIOD:
                plan_details = platform_google_api.fetch_subscription_details_for_base_plan_id(base_plan_id=tx_event.base_plan_id, err=err)

                if log.getEffectiveLevel() <= logging.INFO:
                    payment_label = backend.payment_provider_tx_log_label(tx_payment)
                    grace_ms: int = plan_details.grace_period.milliseconds if plan_details else 0
                    log.info(f'{tx_event.notification.name}+{tx_event.subscription_state.name}; (payment={payment_label}, grace period ms={grace_ms})')

                if not err.has():
                    assert plan_details is not None
                    set_purchase_grace_period_duration(tx_payment               = tx_payment,
                                                       grace_period_duration_ms = plan_details.grace_period.milliseconds,
                                                       tx                       = tx,
                                                       err                      = err)

        case SubscriptionNotificationType.RECOVERED | SubscriptionNotificationType.RENEWED:
            if tx_event.subscription_state == SubscriptionsV2State.ACTIVE:

                if log.getEffectiveLevel() <= logging.INFO:
                    expiry        = base.readable_unix_ts_ms(tx_event.expiry_time.unix_milliseconds)
                    unredeemed    = base.readable_unix_ts_ms(tx_event.event_ts_ms)
                    payment_label = backend.payment_provider_tx_log_label(tx_payment)
                    log.info(f'{tx_event.notification.name}+{tx_event.subscription_state.name}; (payment={payment_label}, plan={tx_event.pro_plan.name}, unredeemed={unredeemed}, expiry={expiry})')

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

                if not err.has():
                    set_purchase_grace_period_duration(tx_payment               = tx_payment,
                                                       tx                       = tx,
                                                       grace_period_duration_ms = base.DEFAULT_GRACE_PERIOD_DURATION_MS,
                                                       err                      = err)

        case SubscriptionNotificationType.CANCELED:
            """Google mentions a case where if a user is on account hold and the canceled event happens they should have entitlement revoked, but entitlement is already expired so this does not need to be handled."""
            if tx_event.subscription_state == SubscriptionsV2State.CANCELED \
            or tx_event.subscription_state == SubscriptionsV2State.EXPIRED:
                if log.getEffectiveLevel() <= logging.INFO:
                    payment_label = backend.payment_provider_tx_log_label(tx_payment)
                    log.info(f'{tx_event.notification.name}+{tx_event.subscription_state.name}; (payment={payment_label}, auto_renew=false)')
                set_payment_auto_renew(tx_payment=tx_payment, auto_renewing=False, tx=tx, err=err)

        case SubscriptionNotificationType.RESTARTED:
            # Only happens when going from CANCELLED to ACTIVE, this is called resubscribing, or re-enabling auto-renew
            if tx_event.subscription_state == SubscriptionsV2State.ACTIVE:
                if log.getEffectiveLevel() <= logging.INFO:
                    payment_label = backend.payment_provider_tx_log_label(tx_payment)
                    log.info(f'{tx_event.notification.name}+{tx_event.subscription_state.name}; (payment={payment_label}, auto_renew=true)')
                set_payment_auto_renew(tx_payment=tx_payment, auto_renewing=True, tx=tx, err=err)

        case SubscriptionNotificationType.REVOKED:
            if tx_event.subscription_state == SubscriptionsV2State.EXPIRED:
                if log.getEffectiveLevel() <= logging.INFO:
                    payment_label = backend.payment_provider_tx_log_label(tx_payment)
                    log.info(f'{tx_event.notification.name}+{tx_event.subscription_state.name}; (payment={payment_label}, auto_renew=false)')
                _ = backend.add_google_revocation_tx(tx                   = tx,
                                                     google_payment_token = tx_payment.google_payment_token,
                                                     revoke_unix_ts_ms    = tx_event.event_ts_ms,
                                                     err                  = err)

        case SubscriptionNotificationType.EXPIRED | SubscriptionNotificationType.ON_HOLD:
            """The revocation function only actually revokes proofs that are not going to self-expire at the end of the UTC day, so
            for the vast majority of users this function wont make any changes to user entitlement. An example of when a proof will
            actually be revoked if the user enters account hold and for some reason their pro proof expires some time in the future
            (later than the end of the UTC day). A user enters account hold if their billing method is still failing after their
            grace period ends.
            """
            if tx_event.subscription_state == SubscriptionsV2State.EXPIRED \
            or tx_event.subscription_state == SubscriptionsV2State.ON_HOLD:

                if log.getEffectiveLevel() <= logging.INFO:
                    payment_label = backend.payment_provider_tx_log_label(tx_payment)
                    log.info(f'{tx_event.notification.name}+{tx_event.subscription_state.name}; (payment={payment_label}, revoke={base.readable_unix_ts_ms(tx_event.event_ts_ms)})')

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
        case SubscriptionNotificationType.DEFERRED |\
            SubscriptionNotificationType.PAUSED |\
            SubscriptionNotificationType.PAUSE_SCHEDULE_CHANGED:
            err.msg_list.append(f'Subscription notificationType {reflect_enum(tx_event.notification)} is unsupported!')

        # NOTE: No-op cases
        case SubscriptionNotificationType.PRICE_CHANGE_CONFIRMED |\
             SubscriptionNotificationType.PRICE_CHANGE_UPDATED |\
             SubscriptionNotificationType.PENDING_PURCHASE_CANCELED |\
             SubscriptionNotificationType.PRICE_STEP_UP_CONSENT_UPDATED:
            pass

    if err.has():
        # Purchase token logging is included in the wrapper function
        err.msg_list.append(f'Failed to handle {reflect_enum(tx_event.notification)} for order_id {tx_payment.google_order_id if len(tx_payment.google_order_id) > 0 else "N/A"}')
        tx.cancel = True

def handle_voided_notification(tx: VoidedPurchaseTxFields, err: base.ErrorSink):
    assert tx.product_type != ProductType.NIL
    match tx.product_type:
        case ProductType.SUBSCRIPTION:
            assert tx.refund_type != RefundType.NIL
            match tx.refund_type:
                case RefundType.FULL_REFUND:
                    # TODO: investigate if we need to implement anything here
                    pass
                case RefundType.QUANTITY_BASED_PARTIAL_REFUND:
                    err.msg_list.append(f'voided purchase refundType {reflect_enum(tx.refund_type)} is unsupported!')
        case ProductType.ONE_TIME:
            err.msg_list.append(f'voided purchase productType {reflect_enum(tx.product_type)} is unsupported!')

    if err.has():
        err.msg_list.append(f'Failed to handle {reflect_enum(tx.refund_type)}')

def parse_notification(body: JSONObject, err: base.ErrorSink) -> ParsedNotification:
    result               = ParsedNotification()
    result.body_version  = json_dict_require_str(body, "version", err)
    result.package_name  = json_dict_require_str(body, "packageName", err)
    result.event_time_ms = json_dict_require_str_coerce_to_int(body, "eventTimeMillis", err)

    if result.package_name != platform_google_api.package_name:
        err.msg_list.append(f'{result.package_name} does not match google_package_name ({platform_google_api.package_name}) from the .INI file!')

    subscription                     = json_dict_optional_obj(body, "subscriptionNotification", err)
    one_time_product                 = json_dict_optional_obj(body, "oneTimeProductNotification", err)
    voided_purchase                  = json_dict_optional_obj(body, "voidedPurchaseNotification", err)
    test_obj                         = json_dict_optional_obj(body, "testNotification", err)

    is_subscription_notification     = subscription     is not None
    is_one_time_product_notification = one_time_product is not None
    is_voided_notification           = voided_purchase  is not None
    is_test_notification             = test_obj         is not None

    unique_notif_keys = is_subscription_notification + is_one_time_product_notification + is_voided_notification + is_test_notification
    if unique_notif_keys == 0:
        err.msg_list.append(f'No subscription notification for {result.package_name} {safe_dump_dict_keys_or_data(body)}')
    elif unique_notif_keys > 1:
        err.msg_list.append(f'Multiple subscription notification for {result.package_name} {safe_dump_dict_keys_or_data(body)}')

    if err.has():
        return result

    if is_subscription_notification:
        result.purchase_token  = json_dict_require_str(subscription, "purchaseToken", err)
        result.payload_version = json_dict_require_str(subscription, "version",  err)
        result.sub_type        = typing.cast(SubscriptionNotificationType, json_dict_require_int_coerce_to_enum(subscription, "notificationType", SubscriptionNotificationType, err))
        result.payload_type    = ParsedNotificationPayloadType.Subscription

    elif is_voided_notification:
        result.purchase_token = json_dict_require_str(voided_purchase, "purchaseToken", err)
        order_id              = json_dict_require_str(voided_purchase, "orderId", err)
        product_type          = json_dict_require_int_coerce_to_enum(voided_purchase, "productType", ProductType, err)
        refund_type           = json_dict_require_int_coerce_to_enum(voided_purchase, "refundType", RefundType, err)

        assert refund_type is not None and product_type is not None and len(result.purchase_token) > 0 and \
        len(order_id) > 0 and isinstance(product_type, ProductType) and isinstance(refund_type, RefundType)
        result.voided         = VoidedPurchaseTxFields(purchase_token = result.purchase_token,
                                                       order_id       = order_id,
                                                       event_ts_ms    = result.event_time_ms,
                                                       product_type   = product_type,
                                                       refund_type    = refund_type)
        result.payload_type = ParsedNotificationPayloadType.Test

    elif is_one_time_product_notification:
        result.payload_type = ParsedNotificationPayloadType.Nil

    elif is_test_notification:
        result.payload_type = ParsedNotificationPayloadType.Test

    return result
