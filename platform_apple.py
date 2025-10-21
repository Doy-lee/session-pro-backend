import flask
import json
import typing
import sqlite3
import dataclasses
import pprint
import logging
import time

from appstoreserverlibrary.models.SendTestNotificationResponse    import SendTestNotificationResponse    as AppleSendTestNotificationResponse
from appstoreserverlibrary.models.CheckTestNotificationResponse   import CheckTestNotificationResponse   as AppleCheckTestNotificationResponse
from appstoreserverlibrary.models.Environment                     import Environment                     as AppleEnvironment
from appstoreserverlibrary.models.Type                            import Type                            as AppleType
from appstoreserverlibrary.models.TransactionReason               import TransactionReason               as AppleTransactionReason
from appstoreserverlibrary.models.JWSTransactionDecodedPayload    import JWSTransactionDecodedPayload    as AppleJWSTransactionDecodedPayload
from appstoreserverlibrary.models.JWSRenewalInfoDecodedPayload    import JWSRenewalInfoDecodedPayload    as AppleJWSRenewalInfoDecodedPayload
from appstoreserverlibrary.models.Data                            import Data                            as AppleData
from appstoreserverlibrary.models.ResponseBodyV2DecodedPayload    import ResponseBodyV2DecodedPayload    as AppleResponseBodyV2DecodedPayload
from appstoreserverlibrary.models.Subtype                         import Subtype                         as AppleSubtype
from appstoreserverlibrary.models.NotificationTypeV2              import NotificationTypeV2              as AppleNotificationV2
from appstoreserverlibrary.models.NotificationHistoryRequest      import NotificationHistoryRequest      as AppleNotificationHistoryRequest
from appstoreserverlibrary.models.NotificationHistoryResponse     import NotificationHistoryResponse     as AppleNotificationHistoryResponse

from appstoreserverlibrary.api_client import (
    AppStoreServerAPIClient as AppleAppStoreServerAPIClient,
    APIException            as AppleAPIException,
)

from appstoreserverlibrary.signed_data_verifier import (
    VerificationException        as AppleVerificationException,
    SignedDataVerifier           as AppleSignedDataVerifier,
)

import base
import server
import backend

log = logging.Logger('APPLE')

@dataclasses.dataclass
class Core:
    app_store_server_api_client:    AppleAppStoreServerAPIClient
    signed_data_verifier:           AppleSignedDataVerifier
    sandbox:                        bool = False
    notification_retry_duration_ms: int = 0
    max_history_lookup_in_days:     int = 0

@dataclasses.dataclass
class DecodedNotification:
    body:         AppleResponseBodyV2DecodedPayload
    tx_info:      AppleJWSTransactionDecodedPayload | None = None
    renewal_info: AppleJWSRenewalInfoDecodedPayload | None = None

FLASK_ROUTE_NOTIFICATIONS_APPLE_APP_CONNECT_SANDBOX: str = '/apple_notifications_v2'
FLASK_CONFIG_PLATFORM_APPLE_CORE_KEY:                str = 'session_pro_backend_platform_apple_core'

# NOTE: Grace period is disabled on Apple but we set a non-zero grace period. First off
# we use a grace period of 0 currently to communicate to the caller that the current
# payment is automatically renewing at the billing cycle.
#
# Then if for Apple we set its grace period to 0 then the platforms are going to
# mistakenly assume that the user does not have an auto-renewing subscription
# and display the wrong flows. So we set a non-zero grace period for Apple.
#
# Whilst it's better to have an independent variable to track whether or not the user
# has an auto-renewing subscription, if we step back and consider the situation,
# technically no payment processor/billing cycle is going to bill exactly on the dot due
# to real-world extenuating situations and so we can opt to grant them a small but
# reasonable grace period of 1 hour.
#
# For now we can opt out of adding yet another variable to track auto-renewing by
# continuing to use the grace period as originally intended.
GRACE_PERIOD_DURATION_MS:                            int = 60 * 60 * 1 * 1000

# The object containing routes that you register onto a Flask app to turn it
# into an app that accepts Apple iOS App Store subscription notifications
flask_blueprint                                     = flask.Blueprint('session-pro-backend-apple', __name__)

def payment_tx_id_label(tx: backend.PaymentProviderTransaction) -> str:
    result = f'TX ID (orig/tx/web) {tx.apple_original_tx_id}/{tx.apple_tx_id}/{tx.apple_web_line_order_tx_id}'
    return result

def pro_plan_from_product_id(product_id: str, err: base.ErrorSink) -> base.ProPlan:
    result = base.ProPlan.Nil
    match product_id:
        case 'com.getsession.org.pro_sub':
            result = base.ProPlan.OneMonth
        case 'com.getsession.org.pro_sub_3_months':
            result = base.ProPlan.ThreeMonth
        case _:
            err.msg_list.append(f'Invalid applie plan_id, unable to determine plan variant: {product_id}')
            assert False, f'Invalid apple plan_id: {product_id}'

    return result

def print_obj(obj: typing.Any) -> str:  # pyright: ignore[reportAny]
    # NOTE: For some reason pprint is unable to pretty print Apple classes. We do it manually ourselves
    result = ''
    if base.UNSAFE_LOGGING:
        attrs  = {attr: getattr(obj, attr) for attr in dir(obj) if not attr.startswith('_') and not callable(getattr(obj, attr))}
        result = f'{pprint.pformat(attrs)}'
    else:
        result = '(obfuscated obj dump)'
    return result

def require_field(field: typing.Any, msg: str, err: base.ErrorSink | None) -> bool:
    result = True
    if field is None:
        result = False
        if err:
            err.msg_list.append(msg)
    return result

def get_platform_refund_expiry_unix_ts_ms(tx: AppleJWSTransactionDecodedPayload) -> int:
    # TODO: It's unclear from the Apple documentation whether or not there is a deadline that a user
    # has to submit a refund request directly through Apple. There are some various off-hand
    # comments on the internet that state this is 90 days but cannot be corroborated on the actual
    # documents provided by Apple.
    #
    # In this instance then we default to informing clients that the user _can_ request a refund
    # through apple for the entirety of their subscription duration as a "sane" default.
    assert tx.expiresDate
    result: int = tx.expiresDate
    return result

def handle_notification_tx(decoded_notification: DecodedNotification, sql_tx: base.SQLTransaction, notification_retry_duration_ms: int, err: base.ErrorSink) -> bool:
    if err.has():
        return False

    assert decoded_notification.body.notificationUUID
    if backend.apple_notification_uuid_is_in_db_tx(sql_tx, decoded_notification.body.notificationUUID):
        return True

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

    if decoded_notification.body.notificationType == AppleNotificationV2.SUBSCRIBED       or \
       decoded_notification.body.notificationType == AppleNotificationV2.DID_RENEW        or \
       decoded_notification.body.notificationType == AppleNotificationV2.ONE_TIME_CHARGE:
        # AppleNotificationV2.ONE_TIME_CHARGE
        #   A notification type that indicates the customer purchased a consumable, non-consumable,
        #   or non-renewing subscription. The App Store also sends this notification when the
        #   customer receives access to a non-consumable product through Family Sharing.
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
        #   For notifications about other product type purchases, see the ONE_TIME_CHARGE
        #   notification type.
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
        tx: AppleJWSTransactionDecodedPayload | None = decoded_notification.tx_info
        if not tx:
            err.msg_list.append(f'{decoded_notification.body.notificationType.name} is missing TX info. {print_obj(tx)}')

        if len(err.msg_list) == 0:
            assert tx
            if require_field(tx.expiresDate,           f'{decoded_notification.body.notificationType.name} is missing TX expires date. {print_obj(tx)}',            err) and \
               require_field(tx.originalTransactionId, f'{decoded_notification.body.notificationType.name} is missing TX original transaction ID. {print_obj(tx)}', err) and \
               require_field(tx.purchaseDate,          f'{decoded_notification.body.notificationType.name} is missing TX purchase date. {print_obj(tx)}',           err) and \
               require_field(tx.transactionId,         f'{decoded_notification.body.notificationType.name} is missing TX transaction ID. {print_obj(tx)}',          err) and \
               require_field(tx.transactionReason,     f'{decoded_notification.body.notificationType.name} is missing TX reason. {print_obj(tx)}',                  err) and \
               require_field(tx.type,                  f'{decoded_notification.body.notificationType.name} is missing TX type. {print_obj(tx)}',                    err) and \
               require_field(tx.productId,             f'{decoded_notification.body.notificationType.name} is missing TX product ID. {print_obj(tx)}',              err) and \
               require_field(tx.webOrderLineItemId,    f'{decoded_notification.body.notificationType.name} is missing TX web order line item ID. {print_obj(tx)}',  err):

                # NOTE: Assert the types for LSP now that we have checked that they exist
                assert isinstance(tx.purchaseDate,          int),                    f'{print_obj(tx)}'
                assert isinstance(tx.originalTransactionId, str),                    f'{print_obj(tx)}'
                assert isinstance(tx.transactionId,         str),                    f'{print_obj(tx)}'
                assert isinstance(tx.expiresDate,           int),                    f'{print_obj(tx)}'
                assert isinstance(tx.transactionReason,     AppleTransactionReason), f'{print_obj(tx)}'
                assert isinstance(tx.type,                  AppleType),              f'{print_obj(tx)}'
                assert isinstance(tx.productId,             str),                    f'{print_obj(tx)}'
                assert isinstance(tx.webOrderLineItemId,    str),                    f'{print_obj(tx)}'

                if decoded_notification.body.notificationType == AppleNotificationV2.ONE_TIME_CHARGE:
                    # NOTE: Verify that the TX type is what we expect it to be
                    expected_type = AppleType.NON_RENEWING_SUBSCRIPTION
                    if tx.type != expected_type:
                        err.msg_list.append(f'{decoded_notification.body.notificationType.name} TX type ({tx.type}) was not the expected value: {expected_type}. {print_obj(tx)}')

                    # NOTE: Verify purchase type is what we expect it to be
                    expected_reason = AppleTransactionReason.PURCHASE
                    if tx.transactionReason != expected_reason:
                        err.msg_list.append(f'{decoded_notification.body.notificationType.name} TX type ({tx.transactionReason}) was not the expected value for a one-time payment: {expected_reason.name}. {print_obj(tx)}')
                else:
                    # NOTE: Verify that the TX type is what we expect it to be
                    expected_type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
                    if tx.type != expected_type:
                        err.msg_list.append(f'{decoded_notification.body.notificationType.name} TX type ({tx.type}) was not the expected value: {expected_type}. {print_obj(tx)}')

                # NOTE: Extract plan
                payment_tx = payment_tx_from_apple_jws_transaction(tx, err)
                pro_plan   = pro_plan_from_product_id(tx.productId, err)

                expiry_unix_ts_ms                 = tx.expiresDate
                unredeemed_unix_ts_ms             = tx.purchaseDate
                platform_refund_expiry_unix_ts_ms = get_platform_refund_expiry_unix_ts_ms(tx)
                auto_renewing                     = True

                if log.getEffectiveLevel() <= logging.DEBUG:
                    expiry        = base.readable_unix_ts_ms(expiry_unix_ts_ms)
                    unredeemed    = base.readable_unix_ts_ms(unredeemed_unix_ts_ms)
                    refund        = base.readable_unix_ts_ms(platform_refund_expiry_unix_ts_ms)
                    log.debug(f'{decoded_notification.body.notificationType.name} for {payment_tx_id_label(payment_tx)}: New payment (expiry/unredeemed/refund expiry) ts = {expiry}/{unredeemed}/{refund}, grace period = {GRACE_PERIOD_DURATION_MS}, auto-renewing = {auto_renewing}')

                # NOTE: Process notification
                sql_tx.cancel = True
                if not err.has():
                    backend.add_unredeemed_payment_tx(tx                                = sql_tx,
                                                      payment_tx                        = payment_tx,
                                                      plan                              = pro_plan,
                                                      unredeemed_unix_ts_ms             = unredeemed_unix_ts_ms,
                                                      platform_refund_expiry_unix_ts_ms = platform_refund_expiry_unix_ts_ms,
                                                      expiry_unix_ts_ms                 = expiry_unix_ts_ms,
                                                      err                               = err)

                if not err.has():
                    _ = backend.update_payment_renewal_info_tx(tx                       = sql_tx,
                                                               payment_tx               = payment_tx,
                                                               grace_period_duration_ms = GRACE_PERIOD_DURATION_MS,
                                                               auto_renewing            = auto_renewing,
                                                               err                      = err)
                sql_tx.cancel = err.has()

    elif decoded_notification.body.notificationType == AppleNotificationV2.DID_CHANGE_RENEWAL_PREF:
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
        tx = decoded_notification.tx_info
        if not tx:
            err.msg_list.append(f'{decoded_notification.body.notificationType.name} is missing TX info {print_obj(tx)}')

        if len(err.msg_list) == 0:
            assert tx
            if require_field(tx.expiresDate,           f'{decoded_notification.body.notificationType.name} is missing TX expires date. {print_obj(tx)}',            err) and \
               require_field(tx.originalTransactionId, f'{decoded_notification.body.notificationType.name} is missing TX original transaction ID. {print_obj(tx)}', err) and \
               require_field(tx.purchaseDate,          f'{decoded_notification.body.notificationType.name} is missing TX purchase date. {print_obj(tx)}',           err) and \
               require_field(tx.transactionId,         f'{decoded_notification.body.notificationType.name} is missing TX transaction ID. {print_obj(tx)}',          err) and \
               require_field(tx.transactionReason,     f'{decoded_notification.body.notificationType.name} is missing TX reason. {print_obj(tx)}',                  err) and \
               require_field(tx.type,                  f'{decoded_notification.body.notificationType.name} is missing TX type. {print_obj(tx)}',                    err) and \
               require_field(tx.productId,             f'{decoded_notification.body.notificationType.name} is missing TX product ID. {print_obj(tx)}',              err) and \
               require_field(tx.webOrderLineItemId,    f'{decoded_notification.body.notificationType.name} is missing TX web order line item ID. {print_obj(tx)}',  err):

                # NOTE: Assert the types for LSP now that we have checked that they exist
                assert isinstance(tx.purchaseDate,          int),                    f'{print_obj(tx)}'
                assert isinstance(tx.originalTransactionId, str),                    f'{print_obj(tx)}'
                assert isinstance(tx.transactionId,         str),                    f'{print_obj(tx)}'
                assert isinstance(tx.expiresDate,           int),                    f'{print_obj(tx)}'
                assert isinstance(tx.transactionReason,     AppleTransactionReason), f'{print_obj(tx)}'
                assert isinstance(tx.type,                  AppleType),              f'{print_obj(tx)}'
                assert isinstance(tx.productId,             str),                    f'{print_obj(tx)}'
                assert isinstance(tx.webOrderLineItemId,    str),                    f'{print_obj(tx)}'

                # NOTE: Verify that the TX type is what we expect it to be
                expected_type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
                if tx.type != expected_type:
                    err.msg_list.append(f'{decoded_notification.body.notificationType.name} TX type ({tx.type}) was not the expected value: {expected_type}. {print_obj(tx)}')

                # NOTE: Extract plan
                pro_plan   = pro_plan_from_product_id(tx.productId, err)
                payment_tx = payment_tx_from_apple_jws_transaction(tx, err)

                # NOTE: Extract components
                if len(err.msg_list) == 0:
                    if not decoded_notification.body.subtype:
                        # NOTE: User is cancelling their downgrade, the downgrade was meant to be
                        # queued for the end of the month. No-op the current payment for the user is
                        # still valid
                        log.debug(f'{decoded_notification.body.notificationType.name} for {payment_tx_id_label(payment_tx)}: No-op')

                    elif decoded_notification.body.subtype == AppleSubtype.DOWNGRADE:
                        # NOTE: User is downgrading to a lesser subscription. Downgrade happens at
                        # end of billing cycle. This is a no-op, we _should_ get a DID_RENEW
                        # notification which handles this for us.
                        #
                        # By virtue of requesting a downgrade (and it activating at the end of the
                        # billing cycle) they are implicitly indicating that they are enabling
                        # auto-renewing.
                        #
                        # The way apple works is that the signed transaction info will be the last
                        # transaction that the user made. In this case the TX info has the current
                        # subscription before the downgrade is to take effect, e.g. it has the TX
                        # info that we need to set auto-renewal back on for
                        log.debug(f'{decoded_notification.body.notificationType.name}+DOWNGRADE for {payment_tx_id_label(payment_tx)}: Grace period = {GRACE_PERIOD_DURATION_MS}, auto-renewing = true')
                        sql_tx.cancel = True
                        _ = backend.update_payment_renewal_info_tx(tx                       = sql_tx,
                                                                   payment_tx               = payment_tx,
                                                                   grace_period_duration_ms = GRACE_PERIOD_DURATION_MS,
                                                                   auto_renewing            = True,
                                                                   err                      = err)
                        sql_tx.cancel = err.has()

                    elif decoded_notification.body.subtype == AppleSubtype.UPGRADE:
                        # User is upgrading to a better subscription. Upgrade happens immediately, current plan is ended.

                        # NOTE: The only link we have to the current plan is the original
                        # transaction ID. It doesn't seem guaranteed that the web order line item ID
                        # is the same in an upgrade (because it's no longer a part of the same
                        # subscription)
                        #
                        # We lookup the latest payment for the original transaction ID and cancel
                        # that

                        expiry_unix_ts_ms                 = tx.expiresDate
                        unredeemed_unix_ts_ms             = tx.purchaseDate
                        platform_refund_expiry_unix_ts_ms = get_platform_refund_expiry_unix_ts_ms(tx)
                        auto_renewing                     = True
                        revoke_unix_ts_ms                 = tx.purchaseDate
                        if log.getEffectiveLevel() <= logging.DEBUG:
                            expiry        = base.readable_unix_ts_ms(expiry_unix_ts_ms)
                            unredeemed    = base.readable_unix_ts_ms(unredeemed_unix_ts_ms)
                            refund        = base.readable_unix_ts_ms(platform_refund_expiry_unix_ts_ms)
                            revoke        = base.readable_unix_ts_ms(tx.purchaseDate)
                            log.debug(f'{decoded_notification.body.notificationType.name}+UPGRADE for {payment_tx_id_label(payment_tx)}: Revoke (orig. TX ID) date = {revoke}, new payment (expiry/unredeemed/refund expiry) ts = {expiry}/{unredeemed}/{refund}, grace period = {GRACE_PERIOD_DURATION_MS}, auto-renewing = {auto_renewing}')

                        sql_tx.cancel = True
                        revoked: bool = backend.add_apple_revocation_tx(tx                   = sql_tx,
                                                                        apple_original_tx_id = tx.originalTransactionId,
                                                                        revoke_unix_ts_ms    = revoke_unix_ts_ms,
                                                                        err                  = err)
                        if not revoked:
                            err.msg_list.append(f'No matching active payment was available to be revoked. {print_obj(tx)}')

                        # NOTE: Submit the upgraded payment (e.g. the new payment)
                        if not err.has():
                            backend.add_unredeemed_payment_tx(tx                                = sql_tx,
                                                              payment_tx                        = payment_tx,
                                                              plan                              = pro_plan,
                                                              expiry_unix_ts_ms                 = expiry_unix_ts_ms,
                                                              unredeemed_unix_ts_ms             = unredeemed_unix_ts_ms,
                                                              platform_refund_expiry_unix_ts_ms = platform_refund_expiry_unix_ts_ms,
                                                              err                               = err)

                        # NOTE: Update grace and set to auto-renewing
                        if not err.has():
                            _ = backend.update_payment_renewal_info_tx(tx                       = sql_tx,
                                                                       payment_tx               = payment_tx,
                                                                       grace_period_duration_ms = GRACE_PERIOD_DURATION_MS,
                                                                       auto_renewing            = True,
                                                                       err                      = err)
                        sql_tx.cancel = err.has()

    elif decoded_notification.body.notificationType == AppleNotificationV2.OFFER_REDEEMED:
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

        tx = decoded_notification.tx_info

        # NOTE: Check the required fields exist
        if tx:
            _ = require_field(tx.expiresDate,           f'{decoded_notification.body.notificationType.name} is missing TX expires date. {print_obj(tx)}',            err)
            _ = require_field(tx.originalTransactionId, f'{decoded_notification.body.notificationType.name} is missing TX original transaction ID. {print_obj(tx)}', err)
            _ = require_field(tx.purchaseDate,          f'{decoded_notification.body.notificationType.name} is missing TX purchase date. {print_obj(tx)}',           err)
            _ = require_field(tx.transactionId,         f'{decoded_notification.body.notificationType.name} is missing TX transaction ID. {print_obj(tx)}',          err)
            _ = require_field(tx.transactionReason,     f'{decoded_notification.body.notificationType.name} is missing TX reason. {print_obj(tx)}',                  err)
            _ = require_field(tx.type,                  f'{decoded_notification.body.notificationType.name} is missing TX type. {print_obj(tx)}',                    err)
            _ = require_field(tx.productId,             f'{decoded_notification.body.notificationType.name} is missing TX product ID. {print_obj(tx)}',              err)
            _ = require_field(tx.webOrderLineItemId,    f'{decoded_notification.body.notificationType.name} is missing TX web order line item ID. {print_obj(tx)}',  err)
        else:
            err.msg_list.append(f'{decoded_notification.body.notificationType.name} is missing TX info {print_obj(tx)}')

        # NOTE: Use the required fields
        if not err.has():
            assert tx # NOTE: Assert the types for LSP now that we have checked that they exist
            assert isinstance(tx.purchaseDate,          int),                    f'{print_obj(tx)}'
            assert isinstance(tx.originalTransactionId, str),                    f'{print_obj(tx)}'
            assert isinstance(tx.transactionId,         str),                    f'{print_obj(tx)}'
            assert isinstance(tx.expiresDate,           str),                    f'{print_obj(tx)}'
            assert isinstance(tx.transactionReason,     AppleTransactionReason), f'{print_obj(tx)}'
            assert isinstance(tx.type,                  AppleType),              f'{print_obj(tx)}'
            assert isinstance(tx.productId,             str),                    f'{print_obj(tx)}'
            assert isinstance(tx.webOrderLineItemId,    str),                    f'{print_obj(tx)}'

            # NOTE: Verify that the TX type is what we expect it to be
            expected_type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
            if tx.type != expected_type:
                err.msg_list.append(f'{decoded_notification.body.notificationType.name} TX type ({tx.type}) was not the expected value: {expected_type}. {print_obj(tx)}')

            # NOTE: Extract plan
            pro_plan: base.ProPlan = pro_plan_from_product_id(tx.productId, err)
            payment_tx             = payment_tx_from_apple_jws_transaction(tx, err)

            # NOTE: Extract components
            if not err.has():
                if not decoded_notification.body.subtype:
                    # NOTE: User is redeeming an offer to start(?) a sub. Submit the payment
                    unredeemed_unix_ts_ms:             int = tx.purchaseDate
                    platform_refund_expiry_unix_ts_ms: int = get_platform_refund_expiry_unix_ts_ms(tx)
                    expiry_unix_ts_ms:                 int = tx.expiresDate

                    if log.getEffectiveLevel() <= logging.DEBUG:
                        expiry        = base.readable_unix_ts_ms(expiry_unix_ts_ms)
                        unredeemed    = base.readable_unix_ts_ms(unredeemed_unix_ts_ms)
                        refund        = base.readable_unix_ts_ms(platform_refund_expiry_unix_ts_ms)
                        log.debug(f'{decoded_notification.body.notificationType.name} for {payment_tx_id_label(payment_tx)}: New payment (unredeemed/refund expiry/expiry) ts = ({unredeemed}/{refund}/{expiry})')

                    backend.add_unredeemed_payment(sql_conn                          = sql_conn,
                                                   payment_tx                        = payment_tx,
                                                   plan                              = pro_plan,
                                                   unredeemed_unix_ts_ms             = tx.purchaseDate,
                                                   platform_refund_expiry_unix_ts_ms = platform_refund_expiry_unix_ts_ms,
                                                   expiry_unix_ts_ms                 = tx.expiresDate,
                                                   err                               = err)

                elif decoded_notification.body.subtype == AppleSubtype.DOWNGRADE:
                    # NOTE: User is downgrading to a lesser subscription. Downgrade happens at
                    # end of billing cycle. This is a no-op, we _should_ get a DID_RENEW
                    # notification which handles this for us at the end of the billing cycle
                    # when they renew.
                    log.debug(f'{decoded_notification.body.notificationType.name}+DOWNGRADE for {payment_tx_id_label(payment_tx)}: No-op, downgrade at next billing cycle')
                    pass

                elif decoded_notification.body.subtype == AppleSubtype.UPGRADE:
                    # NOTE: User is upgrading to a better subscription. Upgrade happens
                    # immediately, current plan is ended. The only link we have to the current
                    # plan is the original transaction ID, so we use that to cancel the old
                    # payment and issue a new one.
                    sql_tx.cancel                     = True
                    auto_renewing                     = True
                    expiry_unix_ts_ms                 = tx.expiresDate
                    unredeemed_unix_ts_ms             = tx.purchaseDate
                    platform_refund_expiry_unix_ts_ms = get_platform_refund_expiry_unix_ts_ms(tx)
                    revoke_unix_ts_ms                 = tx.purchaseDate

                    if log.getEffectiveLevel() <= logging.DEBUG:
                        expiry        = base.readable_unix_ts_ms(expiry_unix_ts_ms)
                        unredeemed    = base.readable_unix_ts_ms(unredeemed_unix_ts_ms)
                        revoke        = base.readable_unix_ts_ms(tx.purchaseDate)
                        refund        = base.readable_unix_ts_ms(platform_refund_expiry_unix_ts_ms)
                        log.debug(f'{decoded_notification.body.notificationType.name}+UPGRADE for {payment_tx_id_label(payment_tx)}: Revoking (orig TX id) at = {revoke}, new payment (expiry/unredeemed/refund ts) = {expiry}/{unredeemed}/{refund}, grace = {GRACE_PERIOD_DURATION_MS}, auto-renewing = {auto_renewing}')

                    revoked = backend.add_apple_revocation_tx(tx                   = sql_tx,
                                                              apple_original_tx_id = tx.originalTransactionId,
                                                              revoke_unix_ts_ms    = revoke_unix_ts_ms,
                                                              err                  = err)
                    if not revoked:
                        err.msg_list.append(f'No matching active payment was available to be revoked. {print_obj(tx)}')

                    # NOTE: Submit the 'new' payment
                    if not err.has():
                        backend.add_unredeemed_payment_tx(tx                                = sql_tx,
                                                          payment_tx                        = payment_tx,
                                                          plan                              = pro_plan,
                                                          expiry_unix_ts_ms                 = expiry_unix_ts_ms,
                                                          unredeemed_unix_ts_ms             = unredeemed_unix_ts_ms,
                                                          platform_refund_expiry_unix_ts_ms = platform_refund_expiry_unix_ts_ms,
                                                          err                               = err)

                    if not err.has():
                        _ = backend.update_payment_renewal_info_tx(tx                       = sql_tx,
                                                                   payment_tx               = payment_tx,
                                                                   grace_period_duration_ms = GRACE_PERIOD_DURATION_MS,
                                                                   auto_renewing            = auto_renewing,
                                                                   err                      = err)

                    sql_tx.cancel = err.has()

    elif decoded_notification.body.notificationType == AppleNotificationV2.REFUND or decoded_notification.body.notificationType == AppleNotificationV2.REVOKE:
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
        tx = decoded_notification.tx_info
        if tx:
            _ = require_field(tx.revocationDate,        f'{decoded_notification.body.notificationType.name} is missing TX revocation date. {print_obj(tx)}',           err)
            _ = require_field(tx.originalTransactionId, f'{decoded_notification.body.notificationType.name} is missing TX original transaction ID. {print_obj(tx)}', err)
        else:
            err.msg_list.append(f'{decoded_notification.body.notificationType.name} is missing TX info {print_obj(tx)}')

        if len(err.msg_list) == 0:
            assert tx # NOTE: Assert the types for LSP now that we have checked that they exist
            assert isinstance(tx.revocationDate,          int), f'{print_obj(tx)}'
            assert isinstance(tx.originalTransactionId, str), f'{print_obj(tx)}'

            # NOTE: Process
            payment_tx = payment_tx_from_apple_jws_transaction(tx, err)
            if not err.has():
                log.debug(f'{decoded_notification.body.notificationType.name} for {payment_tx_id_label(payment_tx)}: Revoke (orig. TX ID) date = {base.readable_unix_ts_ms(tx.revocationDate)}')
                sql_tx.cancel = not backend.add_apple_revocation_tx(tx                   = sql_tx,
                                                                    apple_original_tx_id = tx.originalTransactionId,
                                                                    revoke_unix_ts_ms    = tx.revocationDate,
                                                                    err                  = err)
                if sql_tx.cancel:
                    err.msg_list.append(f'No matching active payment was available to be refunded. {print_obj(tx)}')

    elif decoded_notification.body.notificationType == AppleNotificationV2.REFUND_REVERSED:
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

        # NOTE: Check for required fields
        tx = decoded_notification.tx_info
        if tx:
            _ = require_field(tx.expiresDate,           f'{decoded_notification.body.notificationType.name} is missing TX expires date. {print_obj(tx)}',            err)
            _ = require_field(tx.originalTransactionId, f'{decoded_notification.body.notificationType.name} is missing TX original transaction ID. {print_obj(tx)}', err)
            _ = require_field(tx.transactionId,         f'{decoded_notification.body.notificationType.name} is missing TX transaction ID. {print_obj(tx)}',          err)
            _ = require_field(tx.transactionReason,     f'{decoded_notification.body.notificationType.name} is missing TX reason. {print_obj(tx)}',                  err)
            _ = require_field(tx.type,                  f'{decoded_notification.body.notificationType.name} is missing TX type. {print_obj(tx)}',                    err)
        else:
            err.msg_list.append(f'{decoded_notification.body.notificationType.name} is missing TX info {print_obj(tx)}')

        if not err.has():
            assert tx # NOTE: Assert the types for LSP now that we have checked that they exist
            assert isinstance(tx.expiresDate,           int),                    f'{print_obj(tx)}'
            assert isinstance(tx.originalTransactionId, str),                    f'{print_obj(tx)}'
            assert isinstance(tx.transactionId,         str),                    f'{print_obj(tx)}'
            assert isinstance(tx.transactionReason,     AppleTransactionReason), f'{print_obj(tx)}'
            assert isinstance(tx.type,                  AppleType),              f'{print_obj(tx)}'

            # NOTE: Process
            err.msg_list.append(f'Received TX: {tx}, TODO: this needs to be handled but first check what data we got')
            # TODO: I'm not sure if the notification gives you information about which transaction needs to be reversed.
            # Need to inspect payload

    elif decoded_notification.body.notificationType == AppleNotificationV2.DID_CHANGE_RENEWAL_STATUS:
        # A notification type that, along with its subtype, indicates that the customer made a
        # change to the subscription renewal status. If the subtype is AUTO_RENEW_ENABLED, the
        # customer reenabled subscription auto-renewal. If the subtype is AUTO_RENEW_DISABLED, the
        # customer turned off subscription auto-renewal, or the App Store turned off subscription
        # auto-renewal after the customer requested a refund.
        #
        # Triggers (https://developer.apple.com/documentation/appstoreservernotifications/notificationtype#Handle-use-cases-for-in-app-purchase-life-cycle-events)
        tx = decoded_notification.tx_info
        if not tx:
            err.msg_list.append(f'{decoded_notification.body.notificationType.name} is missing TX info {print_obj(tx)}')

        if not decoded_notification.body.subtype == AppleSubtype.AUTO_RENEW_DISABLED and not decoded_notification.body.subtype == AppleSubtype.AUTO_RENEW_ENABLED:
            err.msg_list.append(f'Received TX: {print_obj(tx)}, with unrecognised subtype for a DID_CHANGE_RENEWAL_STATUS notification')

        if not err.has():
            assert tx
            payment_tx = payment_tx_from_apple_jws_transaction(tx, err)
            if not err.has():
                auto_renewing: bool = decoded_notification.body.subtype == AppleSubtype.AUTO_RENEW_ENABLED
                log.debug(f'{decoded_notification.body.notificationType.name} for {payment_tx_id_label(payment_tx)}: Auto-renewing = {auto_renewing}, grace period = {GRACE_PERIOD_DURATION_MS}')
                _ = backend.update_payment_renewal_info_tx(tx                       = sql_tx,
                                                           payment_tx               = payment_tx,
                                                           grace_period_duration_ms = None,
                                                           auto_renewing            = auto_renewing,
                                                           err                      = err)

    elif decoded_notification.body.notificationType == AppleNotificationV2.DID_FAIL_TO_RENEW:
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
        renewal = decoded_notification.renewal_info
        tx      = decoded_notification.tx_info
        if not renewal:
            err.msg_list.append(f'{decoded_notification.body.notificationType.name} is missing renewal info {print_obj(renewal)}')
        if not tx:
            err.msg_list.append(f'{decoded_notification.body.notificationType.name} is missing TX info {print_obj(tx)}')

        if not err.has():
            assert renewal
            _ = require_field(renewal.gracePeriodExpiresDate, f'{decoded_notification.body.notificationType.name} is missing renewal grace period expires date. {print_obj(renewal)}', err)

        if not err.has():
            assert renewal
            assert tx
            payment_tx: backend.PaymentProviderTransaction = payment_tx_from_apple_jws_transaction(tx, err)
            if not err.has():
                if not decoded_notification.body.subtype:
                    log.debug(f'{decoded_notification.body.notificationType.name} for {payment_tx_id_label(payment_tx)}: Grace period ended')

                elif decoded_notification.body.subtype == AppleSubtype.GRACE_PERIOD:
                    log.debug(f'{decoded_notification.body.notificationType.name} for {payment_tx_id_label(payment_tx)}: Auto-renewing = true, grace period = {renewal.gracePeriodExpiresDate}')
                    _ = backend.update_payment_renewal_info(sql_conn                 = sql_conn,
                                                            payment_tx               = payment_tx,
                                                            grace_period_duration_ms = renewal.gracePeriodExpiresDate,
                                                            auto_renewing            = True,
                                                            err                      = err)
                else:
                    err.msg_list.append(f'Received TX: {print_obj(tx)}, with unrecognised subtype for a DID_FAIL_TO_RENEW notification')

    elif decoded_notification.body.notificationType == AppleNotificationV2.TEST:
        # NOTE: Test notification that we can invoke for testing. No-op
        pass

    # NOTE: Notifications that we do not care about handling
    elif decoded_notification.body.notificationType == AppleNotificationV2.EXPIRED              or \
         decoded_notification.body.notificationType == AppleNotificationV2.REFUND_DECLINED      or \
         decoded_notification.body.notificationType == AppleNotificationV2.GRACE_PERIOD_EXPIRED or \
         decoded_notification.body.notificationType == AppleNotificationV2.CONSUMPTION_REQUEST  or \
         decoded_notification.body.notificationType == AppleNotificationV2.PRICE_INCREASE:

        tx         = decoded_notification.tx_info
        payment_tx = backend.PaymentProviderTransaction()
        if tx:
            payment_tx = payment_tx_from_apple_jws_transaction(tx, err)
        else:
            err.msg_list.append(f'{decoded_notification.body.notificationType.name} is missing TX info {print_obj(tx)}')

        if not err.has():
            log.debug(f'{decoded_notification.body.notificationType.name} for {payment_tx_id_label(payment_tx)}: No-op')

            if decoded_notification.body.notificationType == AppleNotificationV2.EXPIRED:
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

            elif decoded_notification.body.notificationType == AppleNotificationV2.REFUND_DECLINED:
                # A notification type that indicates the App Store declined a refund request.
                #
                # NOTE: No-op, the user is still entitled to Session Pro, we either get a REFUND or
                # REFUND_DECLINED, they are mutually exclusive. In the REFUND case we will end their
                # entitlement.
                pass

            elif decoded_notification.body.notificationType == AppleNotificationV2.GRACE_PERIOD_EXPIRED:
                # A notification type that indicates that the billing grace period has ended without
                # renewing the subscription, so you can turn off access to the service or content. Inform
                # the customer that there may be an issue with their billing information. The App Store
                # continues to retry billing for 60 days, or until the customer resolves their billing issue
                # or cancels their subscription, whichever comes first.
                #
                # Triggers (https://developer.apple.com/documentation/appstoreservernotifications/notificationtype#Handle-use-cases-for-in-app-purchase-life-cycle-events)
                #
                # NOTE: No-op, the Session Pro proofs have an expiry date embedded into them and that is
                # handled by the backend itself.
                pass

            elif decoded_notification.body.notificationType == AppleNotificationV2.CONSUMPTION_REQUEST:
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
                assert decoded_notification.body.notificationType == AppleNotificationV2.PRICE_INCREASE
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
                # NOTE: No-op, the apps do not respond to price increases
                pass


    # NOTE: Erroneous cases, scenarios we don't support/should never receive a notification for
    elif decoded_notification.body.notificationType == AppleNotificationV2.EXTERNAL_PURCHASE_TOKEN or \
         decoded_notification.body.notificationType == AppleNotificationV2.RENEWAL_EXTENDED        or \
         decoded_notification.body.notificationType == AppleNotificationV2.RENEWAL_EXTENSION:

        if decoded_notification.tx_info:
            payment_tx: backend.PaymentProviderTransaction = payment_tx_from_apple_jws_transaction(decoded_notification.tx_info, err)
            log.debug(f'{decoded_notification.body.notificationType.name} for {payment_tx_id_label(payment_tx)}: No-op')

        if decoded_notification.body.notificationType == AppleNotificationV2.EXTERNAL_PURCHASE_TOKEN:
           err.msg_list.append(f'Received notification "{decoded_notification.body.notificationType.name}", but we do not support 3rd party stores through Apple')
        elif decoded_notification.body.notificationType == AppleNotificationV2.RENEWAL_EXTENSION or decoded_notification.body.notificationType == AppleNotificationV2.RENEWAL_EXTENDED:
           err.msg_list.append(f'Received notification "{decoded_notification.body.notificationType.name}", but we don\'t handle issuing the extension of a subscription renewal (e.g.: to compensate for service outages)')
    else:
        err.msg_list.append(f'Received notification {decoded_notification.body.notificationType} that wasn\'t explicitly handled')

    result = len(err.msg_list) == 0

    # TODO: Apple does not use the signedDate as the timestamp that the notification was generated
    # at. But it's close enough-ish
    if result:
        assert decoded_notification.body.signedDate
        expiry_unix_ts_ms: int  = decoded_notification.body.signedDate + notification_retry_duration_ms
        backend.add_apple_notification_uuid_tx(tx                = sql_tx,
                                               uuid              = decoded_notification.body.notificationUUID,
                                               expiry_unix_ts_ms = expiry_unix_ts_ms)
    return result

def handle_notification(decoded_notification: DecodedNotification, sql_conn: sqlite3.Connection, notification_retry_duration_ms: int, err: base.ErrorSink) -> bool:
  result = False
  with base.SQLTransaction(sql_conn) as tx:
    result = handle_notification_tx(decoded_notification, tx, notification_retry_duration_ms, err)
  return result

@flask_blueprint.route(FLASK_ROUTE_NOTIFICATIONS_APPLE_APP_CONNECT_SANDBOX, methods=['POST'])
def notifications_apple_app_connect_sandbox() -> flask.Response:
    # NOTE: Extract notification from payload
    get: server.GetJSONFromFlaskRequest = server.get_json_from_flask_request(flask.request)
    if len(get.err_msg):
        log.error(f'Failed to parse notification as JSON: {flask.request.data}')
        flask.abort(500)

    log.debug(f'Received notification: {json.dumps(get.json, indent=1)}\n')
    assert isinstance(get.json, dict)
    assert FLASK_CONFIG_PLATFORM_APPLE_CORE_KEY in flask.current_app.config
    assert isinstance(flask.current_app.config[FLASK_CONFIG_PLATFORM_APPLE_CORE_KEY], Core)
    core = typing.cast(Core, flask.current_app.config[FLASK_CONFIG_PLATFORM_APPLE_CORE_KEY])

    if 'signedPayload' not in get.json:
        log.error(f'Failed to parse notification, signedPayload key was missing: {base.safe_dump_dict_keys_or_data(get.json)}')
        flask.abort(500)

    signed_payload = get.json['signedPayload']
    if not isinstance(signed_payload, str):
        log.error(f'Failed to parse notification, signed payload was not a string: {type(signed_payload)}')
        flask.abort(500)

    # NOTE: Decode the notification
    resp: AppleResponseBodyV2DecodedPayload   = core.signed_data_verifier.verify_and_decode_notification(signed_payload)

    # NOTE: Handle the notification
    err                                       = base.ErrorSink()
    decoded_notification: DecodedNotification = decoded_notification_from_apple_response_body_v2(resp, core.signed_data_verifier, err)
    with server.open_db_from_flask_request_context(flask.current_app) as db:
        _ = handle_notification(decoded_notification, db.sql_conn, core.notification_retry_duration_ms, err)

    # NOTE: Handle errors
    if err.has():
        # NOTE: Record the error under the payment token if possible to propagate to clients
        if decoded_notification.tx_info and decoded_notification.tx_info.originalTransactionId:
            user_error = backend.UserError(
                provider             = base.PaymentProvider.iOSAppStore,
                apple_original_tx_id = decoded_notification.tx_info.originalTransactionId,
            )
            with server.open_db_from_flask_request_context(flask.current_app) as db:
                backend.add_user_error(sql_conn=db.sql_conn, error=user_error, unix_ts_ms=int(time.time() * 1000))

        # NOTE: Log and abort request
        log.error(f'Failed to parse notification ({resp.signedDate}) signed payload was:\n{signed_payload}\nErrors:' + '\n  '.join(err.msg_list))
        flask.abort(500)

    return flask.Response(status=200)

def trigger_test_notification(client: AppleAppStoreServerAPIClient, verifier: AppleSignedDataVerifier):
    try:
        response_test_notif: AppleSendTestNotificationResponse = client.request_test_notification()
        log.debug('Send test notif: ', response_test_notif)

        notification_token = response_test_notif.testNotificationToken
        if notification_token:
            response_check_test_notif: AppleCheckTestNotificationResponse = client.get_test_notification_status(test_notification_token=notification_token)
            log.debug('Check test notif: ', response_check_test_notif)
            if response_check_test_notif.signedPayload:
                decoded_response: AppleResponseBodyV2DecodedPayload = verifier.verify_and_decode_notification(signed_payload=response_check_test_notif.signedPayload)
                log.info('Decoded test response: ', decoded_response)
    except AppleAPIException as e:
        log.error(f'Failed to decode test notification: {e}')

def init(key_id: str, issuer_id: str, bundle_id: str, app_id: int | None, key_bytes: bytes, root_certs: list[bytes], sandbox_env: bool) -> Core:
    apple_env                   = AppleEnvironment.SANDBOX if sandbox_env else AppleEnvironment.PRODUCTION
    app_store_server_api_client = AppleAppStoreServerAPIClient(signing_key = key_bytes,
                                                               key_id      = key_id,
                                                               issuer_id   = issuer_id,
                                                               bundle_id   = bundle_id,
                                                               environment = apple_env)

    signed_data_verifier        = AppleSignedDataVerifier(root_certificates    = root_certs,
                                                          enable_online_checks = True,
                                                          environment          = apple_env,
                                                          bundle_id            = bundle_id,
                                                          app_apple_id         = app_id)

    result                            = Core(app_store_server_api_client, signed_data_verifier)
    result.sandbox                    = sandbox_env
    result.max_history_lookup_in_days = 30 if sandbox_env else 180

    # NOTE: Apple retries 1, 12, 24 ... hours after the previous attempt
    # NOTE: Then add a 30min buffer just in-case
    if result.sandbox == False:
        result.notification_retry_duration_ms  = (1 + 12 + 24 + 48 + 72) * 60 * 1000
        result.notification_retry_duration_ms += (30 * 60) * 1000
    return result

def catchup_on_missed_notifications(core: Core, sql_conn: sqlite3.Connection, end_unix_ts_ms: int):
    # NOTE: Lock the DB and catch on up missed notifications
    with base.SQLTransaction(conn=sql_conn, mode=base.SQLTransactionMode.Exclusive) as tx:
        # NOTE: Do a catch-up check only if it's been 30mins since the last checkup. UWSGI spawns
        # multiple processes that call the main entry-point so this naturally dedupes all those
        # processes racing to try and execute this
        runtime:               backend.RuntimeRow = backend.get_runtime_tx(tx)
        ms_since_last_catchup: int                = end_unix_ts_ms - runtime.apple_notification_checkpoint_unix_ts_ms
        ms_between_catchup:    int                = (60 * 30) * 1000 # 30 minutes
        do_catchup:            bool               = ms_since_last_catchup >= ms_between_catchup

        if do_catchup:
            # NOTE: Setup request
            min_start_date:      int = end_unix_ts_ms - (core.max_history_lookup_in_days * base.MILLISECONDS_IN_DAY)
            history_req              = AppleNotificationHistoryRequest()
            history_req.onlyFailures = True
            history_req.startDate    = max(min_start_date, runtime.apple_notification_checkpoint_unix_ts_ms)
            history_req.endDate      = end_unix_ts_ms
            log.info(f'Checking for missed notifications from {base.readable_unix_ts_ms(history_req.startDate)} => {base.readable_unix_ts_ms(history_req.endDate)}')

            if runtime.apple_notification_checkpoint_unix_ts_ms != 0 and runtime.apple_notification_checkpoint_unix_ts_ms < min_start_date:
                log.warning(f'Apple only allows retrieving 180 days worth of notifications (i.e. {base.readable_unix_ts_ms(min_start_date)}). ' +
                             'Last notification checkpoint was at {base.readable_unix_ts_ms(runtime.apple_notification_checkpoint_unix_ts_ms)} which is older than the history that can be recalled')

            # NOTE: Iterate the paginated API
            failed             = False
            history_page_token = None
            handled_notifs     = 0
            total_notifs       = 0
            err                = base.ErrorSink()
            while True:
                history_resp: AppleNotificationHistoryResponse = core.app_store_server_api_client.get_notification_history(history_page_token, notification_history_request=history_req)
                if history_resp.notificationHistory:
                    total_notifs += len(history_resp.notificationHistory)
                    if failed == False:
                        for it in history_resp.notificationHistory:
                            # NOTE: Decode and handle
                            assert it.signedPayload
                            resp:                 AppleResponseBodyV2DecodedPayload = core.signed_data_verifier.verify_and_decode_notification(it.signedPayload)
                            decoded_notification: DecodedNotification               = decoded_notification_from_apple_response_body_v2(resp, core.signed_data_verifier, err)
                            handled:              bool                              = handle_notification_tx(decoded_notification, tx, core.notification_retry_duration_ms, err)
                            if handled == False:
                                failed            = True
                                assert tx.cancel == True
                                err.msg_list.append(f'Failed to handle missed notification {it}')
                                break

                            handled_notifs += 1
                if history_resp.hasMore == False:
                    break
                history_page_token = history_resp.paginationToken

            if err.has():
                assert tx.cancel == True
                log.error(f'Processed {handled_notifs}/{total_notifs} missed notifications but encountered errors, rolling back:\n' + '\n  '.join(err.msg_list))
            else:
                backend.set_apple_notification_checkpoint_unix_ts_ms(tx, history_req.endDate)
                log.info(f'Processed {handled_notifs}/{total_notifs} missed notifications, checkpointed from {base.readable_unix_ts_ms(history_req.startDate)} => {base.readable_unix_ts_ms(history_req.endDate)}')
        else:
            mins_between_catchup    = (ms_between_catchup / 1000) / 60
            mins_since_last_catchup = (ms_since_last_catchup / 1000) / 60
            log.debug(f'Skipping catchup of missed notifications last checked {mins_since_last_catchup:.1f} mins ago (catchup occurs every {mins_between_catchup} mins)')

def equip_flask_routes(core: Core, flask: flask.Flask):
    flask.register_blueprint(flask_blueprint)

    # NOTE: Add the core data structure for Apple into the flask config dictionary. This makes it
    # accessible in routes across concurrent connections.
    flask.config[FLASK_CONFIG_PLATFORM_APPLE_CORE_KEY] = core

def decoded_notification_from_apple_response_body_v2(body: AppleResponseBodyV2DecodedPayload, verifier: AppleSignedDataVerifier, err: base.ErrorSink | None) -> DecodedNotification:
    result = DecodedNotification(body=body)

    raw_signed_tx_info:      str | None = None
    raw_signed_renewal_info: str | None = None
    if require_field(body.data, f'{body.notificationType} notification is missing body\'s data', err):
        assert isinstance(body.data, AppleData)
        if require_field(body.data.signedTransactionInfo, f'{body.notificationType} notification is missing body data\'s signedTransactionInfo', err):
            assert isinstance(body.data.signedTransactionInfo, str)
            raw_signed_tx_info = body.data.signedTransactionInfo
        if require_field(body.data.signedRenewalInfo, f'{body.notificationType} notification is missing body data\'s signedRenewalInfo', err):
            assert isinstance(body.data.signedRenewalInfo, str)
            raw_signed_renewal_info = body.data.signedRenewalInfo

    # Parse and verify the raw TX
    if raw_signed_tx_info:
        try:
            result.tx_info = verifier.verify_and_decode_signed_transaction(raw_signed_tx_info)
        except AppleVerificationException as e:
            if err:
                err.msg_list.append(f'{body.notificationType} notification signed TX info failed to be verified, {e}')

    if raw_signed_renewal_info:
        try:
            result.renewal_info = verifier.verify_and_decode_renewal_info(raw_signed_renewal_info)
        except AppleVerificationException as e:
            if err:
                err.msg_list.append(f'{body.notificationType} notification signed TX renewal info failed to be verified, {e}')

    return result

def payment_tx_from_apple_jws_transaction(tx: AppleJWSTransactionDecodedPayload, err: base.ErrorSink) -> backend.PaymentProviderTransaction:
    result = backend.PaymentProviderTransaction()
    if not tx.transactionId:
        err.msg_list.append('Failed to convert Apple TX to payment TX, transaction ID is missing')
    if not tx.originalTransactionId:
        err.msg_list.append('Failed to convert Apple TX to payment TX, original transaction ID is missing')

    if len(err.msg_list) == 0:
        assert tx.originalTransactionId, print_obj(tx)
        assert tx.transactionId,         print_obj(tx)
        result.provider             = base.PaymentProvider.iOSAppStore
        result.apple_original_tx_id = tx.originalTransactionId
        result.apple_tx_id          = tx.transactionId
        if tx.webOrderLineItemId:
            result.apple_web_line_order_tx_id = tx.webOrderLineItemId
    return result
