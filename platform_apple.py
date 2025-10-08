import flask
import json
import typing
import base
import backend
import sqlite3
import sys
import time
import dataclasses
import pprint
from datetime import datetime

from appstoreserverlibrary.models.SendTestNotificationResponse  import SendTestNotificationResponse  as AppleSendTestNotificationResponse
from appstoreserverlibrary.models.CheckTestNotificationResponse import CheckTestNotificationResponse as AppleCheckTestNotificationResponse
from appstoreserverlibrary.models.Environment                   import Environment                   as AppleEnvironment
from appstoreserverlibrary.models.Type                          import Type                          as AppleType
from appstoreserverlibrary.models.TransactionReason             import TransactionReason             as AppleTransactionReason
from appstoreserverlibrary.models.JWSTransactionDecodedPayload  import JWSTransactionDecodedPayload  as AppleJWSTransactionDecodedPayload
from appstoreserverlibrary.models.JWSRenewalInfoDecodedPayload  import JWSRenewalInfoDecodedPayload  as AppleJWSRenewalInfoDecodedPayload
from appstoreserverlibrary.models.Data                          import Data                          as AppleData
from appstoreserverlibrary.models.ResponseBodyV2DecodedPayload  import ResponseBodyV2DecodedPayload  as AppleResponseBodyV2DecodedPayload
from appstoreserverlibrary.models.Subtype                       import Subtype                       as AppleSubtype
from appstoreserverlibrary.models.NotificationTypeV2            import NotificationTypeV2            as AppleNotificationV2

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

@dataclasses.dataclass
class Core:
    app_store_server_api_client: AppleAppStoreServerAPIClient
    signed_data_verifier:        AppleSignedDataVerifier

@dataclasses.dataclass
class DecodedNotification:
    body:         AppleResponseBodyV2DecodedPayload
    tx_info:      AppleJWSTransactionDecodedPayload | None
    renewal_info: AppleJWSRenewalInfoDecodedPayload | None

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

def pro_plan_from_product_id(product_id: str, err: base.ErrorSink) -> backend.ProPlanType:
    result = backend.ProPlanType.Nil
    match product_id:
        case 'com.getsession.org.pro_sub':
            return backend.ProPlanType.OneMonth
        case 'com.getsession.org.pro_sub_3_months':
            return backend.ProPlanType.ThreeMonth
        case _:
            assert False, f'Invalid apple plan_id: {product_id}'
            err.msg_list.append(f'Invalid applie plan_id, unable to determine plan variant: {product_id}')
    return result

def print_obj(obj: typing.Any) -> str:
    # NOTE: For some reason pprint is unable to pretty print Apple classes. We do it manually ourselves
    attrs  = {attr: getattr(obj, attr) for attr in dir(obj) if not attr.startswith('_') and not callable(getattr(obj, attr))}
    result = f'{pprint.pformat(attrs)}'
    return result

def require_field(field: typing.Any, msg: str, err: base.ErrorSink | None) -> bool:
    result = True
    if field is None:
        result = False
        if err:
            err.msg_list.append(msg)
    return result

def handle_notification(decoded_notification: DecodedNotification, sql_conn: sqlite3.Connection, err: base.ErrorSink):
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
            err.msg_list.append(f'{decoded_notification.body.notificationType} is missing TX info {print_obj(tx)}')

        if len(err.msg_list) == 0:
            assert tx
            if require_field(tx.expiresDate,           f'{decoded_notification.body.notificationType} is missing TX expires date. {print_obj(tx)}',            err) and \
               require_field(tx.originalTransactionId, f'{decoded_notification.body.notificationType} is missing TX original transaction ID. {print_obj(tx)}', err) and \
               require_field(tx.purchaseDate,          f'{decoded_notification.body.notificationType} is missing TX purchase date. {print_obj(tx)}',           err) and \
               require_field(tx.transactionId,         f'{decoded_notification.body.notificationType} is missing TX transaction ID. {print_obj(tx)}',          err) and \
               require_field(tx.transactionReason,     f'{decoded_notification.body.notificationType} is missing TX reason. {print_obj(tx)}',                  err) and \
               require_field(tx.type,                  f'{decoded_notification.body.notificationType} is missing TX type. {print_obj(tx)}',                    err) and \
               require_field(tx.productId,             f'{decoded_notification.body.notificationType} is missing TX product ID. {print_obj(tx)}',              err) and \
               require_field(tx.webOrderLineItemId,    f'{decoded_notification.body.notificationType} is missing TX web order line item ID. {print_obj(tx)}',  err):

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
                        err.msg_list.append(f'{decoded_notification.body.notificationType} TX type ({tx.type}) was not the expected value: {expected_type}. {print_obj(tx)}')

                    # NOTE: Verify purchase type is what we expect it to be
                    expected_reason = AppleTransactionReason.PURCHASE
                    if tx.transactionReason != expected_reason:
                        err.msg_list.append(f'{decoded_notification.body.notificationType} TX type ({tx.transactionReason}) was not the expected value for a one-time payment: {expected_reason}. {print_obj(tx)}')
                else:
                    # NOTE: Verify that the TX type is what we expect it to be
                    expected_type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
                    if tx.type != expected_type:
                        err.msg_list.append(f'{decoded_notification.body.notificationType} TX type ({tx.type}) was not the expected value: {expected_type}. {print_obj(tx)}')

                # NOTE: Extract plan
                payment_tx: backend.PaymentProviderTransaction = payment_tx_from_apple_jws_transaction(tx, err)
                pro_plan:   backend.ProPlanType                = pro_plan_from_product_id(tx.productId, err)

                # NOTE: Process notification
                with base.SQLTransaction(sql_conn) as sql_tx:
                    sql_tx.cancel = True
                    if not err.has():
                        backend.add_unredeemed_payment_tx(tx                                = sql_tx,
                                                          payment_tx                        = payment_tx,
                                                          plan                              = pro_plan,
                                                          unredeemed_unix_ts_ms             = tx.purchaseDate,
                                                          platform_refund_expiry_unix_ts_ms = 0, # TODO
                                                          expiry_unix_ts_ms                 = tx.expiresDate,
                                                          err                               = err)

                    if not err.has():
                        _ = backend.update_payment_renewal_info_tx(tx                       = sql_tx,
                                                                   payment_tx               = payment_tx,
                                                                   grace_period_duration_ms = GRACE_PERIOD_DURATION_MS,
                                                                   auto_renewing            = True,
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
            err.msg_list.append(f'{decoded_notification.body.notificationType} is missing TX info {print_obj(tx)}')

        if len(err.msg_list) == 0:
            assert tx
            if require_field(tx.expiresDate,           f'{decoded_notification.body.notificationType} is missing TX expires date. {print_obj(tx)}',            err) and \
               require_field(tx.originalTransactionId, f'{decoded_notification.body.notificationType} is missing TX original transaction ID. {print_obj(tx)}', err) and \
               require_field(tx.purchaseDate,          f'{decoded_notification.body.notificationType} is missing TX purchase date. {print_obj(tx)}',           err) and \
               require_field(tx.transactionId,         f'{decoded_notification.body.notificationType} is missing TX transaction ID. {print_obj(tx)}',          err) and \
               require_field(tx.transactionReason,     f'{decoded_notification.body.notificationType} is missing TX reason. {print_obj(tx)}',                  err) and \
               require_field(tx.type,                  f'{decoded_notification.body.notificationType} is missing TX type. {print_obj(tx)}',                    err) and \
               require_field(tx.productId,             f'{decoded_notification.body.notificationType} is missing TX product ID. {print_obj(tx)}',              err) and \
               require_field(tx.webOrderLineItemId,    f'{decoded_notification.body.notificationType} is missing TX web order line item ID. {print_obj(tx)}',  err):

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
                    err.msg_list.append(f'{decoded_notification.body.notificationType} TX type ({tx.type}) was not the expected value: {expected_type}. {print_obj(tx)}')

                # NOTE: Extract plan
                pro_plan:  backend.ProPlanType = pro_plan_from_product_id(tx.productId, err)
                payment_tx                     = payment_tx_from_apple_jws_transaction(tx, err)

                # NOTE: Extract components
                if len(err.msg_list) == 0:
                    if not decoded_notification.body.subtype:
                        # NOTE: User is cancelling their downgrade, the downgrade was meant to be
                        # queued for the end of the month. By virtue of requesting a downgrade (and
                        # it activating at the end of the billing cycle) they are implicitly
                        # indicating that they are enabling auto-renewing.
                        #
                        # The way apple works is that the signed transaction info will be the last
                        # transaction that the user made. In this case the TX info has the current
                        # subscription before the downgrade is to take effect, e.g. it has the TX
                        # info that we need to set auto-renewal back on for
                        with base.SQLTransaction(sql_conn) as sql_tx:
                            sql_tx.cancel = True
                            _ = backend.update_payment_renewal_info_tx(tx                       = sql_tx,
                                                                       payment_tx               = payment_tx,
                                                                       grace_period_duration_ms = None,
                                                                       auto_renewing            = True,
                                                                       err                      = err)
                            sql_tx.cancel = err.has()

                    elif decoded_notification.body.subtype == AppleSubtype.DOWNGRADE:
                        # NOTE: User is downgrading to a lesser subscription. Downgrade happens at
                        # end of billing cycle. This is a no-op, we _should_ get a DID_RENEW
                        # notification which handles this for us.
                        pass

                    elif decoded_notification.body.subtype == AppleSubtype.UPGRADE:
                        # User is upgrading to a better subscription. Upgrade happens immediately, current plan is ended.

                        # NOTE: The only link we have to the current plan is the original
                        # transaction ID. It doesn't seem guaranteed that the web order line item ID
                        # is the same in an upgrade (because it's no longer a part of the same
                        # subscription)
                        #
                        # We lookup the latest payment for the original transaction ID and cancel
                        # that
                        with base.SQLTransaction(sql_conn) as sql_tx:
                            sql_tx.cancel = True
                            refunded: bool = backend.refund_apple_payment(tx                   = sql_tx,
                                                                          apple_original_tx_id = tx.originalTransactionId,
                                                                          refund_unix_ts_ms    = tx.purchaseDate)
                            if not refunded:
                                err.msg_list.append(f'No matching active payment was available to be refunded. {print_obj(tx)}')

                            # NOTE: Submit the upgraded payment (e.g. the new payment)
                            if not err.has():
                                backend.add_unredeemed_payment_tx(tx                                = sql_tx,
                                                                  payment_tx                        = payment_tx,
                                                                  plan                              = pro_plan,
                                                                  expiry_unix_ts_ms                 = tx.expiresDate,
                                                                  unredeemed_unix_ts_ms             = tx.purchaseDate,
                                                                  platform_refund_expiry_unix_ts_ms = 0, # TODO
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
            _ = require_field(tx.expiresDate,           f'{decoded_notification.body.notificationType} is missing TX expires date. {print_obj(tx)}',            err)
            _ = require_field(tx.originalTransactionId, f'{decoded_notification.body.notificationType} is missing TX original transaction ID. {print_obj(tx)}', err)
            _ = require_field(tx.purchaseDate,          f'{decoded_notification.body.notificationType} is missing TX purchase date. {print_obj(tx)}',           err)
            _ = require_field(tx.transactionId,         f'{decoded_notification.body.notificationType} is missing TX transaction ID. {print_obj(tx)}',          err)
            _ = require_field(tx.transactionReason,     f'{decoded_notification.body.notificationType} is missing TX reason. {print_obj(tx)}',                  err)
            _ = require_field(tx.type,                  f'{decoded_notification.body.notificationType} is missing TX type. {print_obj(tx)}',                    err)
            _ = require_field(tx.productId,             f'{decoded_notification.body.notificationType} is missing TX product ID. {print_obj(tx)}',              err)
            _ = require_field(tx.webOrderLineItemId,    f'{decoded_notification.body.notificationType} is missing TX web order line item ID. {print_obj(tx)}',  err)
        else:
            err.msg_list.append(f'{decoded_notification.body.notificationType} is missing TX info {print_obj(tx)}')

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
                err.msg_list.append(f'{decoded_notification.body.notificationType} TX type ({tx.type}) was not the expected value: {expected_type}. {print_obj(tx)}')

            # NOTE: Extract plan
            pro_plan: backend.ProPlanType = pro_plan_from_product_id(tx.productId, err)
            payment_tx                    = payment_tx_from_apple_jws_transaction(tx, err)

            # NOTE: Extract components
            if not err.has():
                if not decoded_notification.body.subtype:
                    # NOTE: User is redeeming an offer to start(?) a sub. Submit the payment
                    backend.add_unredeemed_payment(sql_conn                          = sql_conn,
                                                   payment_tx                        = payment_tx,
                                                   plan                              = pro_plan,
                                                   unredeemed_unix_ts_ms             = tx.purchaseDate,
                                                   platform_refund_expiry_unix_ts_ms = 0, # TODO
                                                   expiry_unix_ts_ms                 = tx.expiresDate,
                                                   err                               = err)

                elif decoded_notification.body.subtype == AppleSubtype.DOWNGRADE:
                    # NOTE: User is downgrading to a lesser subscription. Downgrade happens at
                    # end of billing cycle. This is a no-op, we _should_ get a DID_RENEW
                    # notification which handles this for us at the end of the billing cycle
                    # when they renew.
                    pass

                elif decoded_notification.body.subtype == AppleSubtype.UPGRADE:
                    # NOTE: User is upgrading to a better subscription. Upgrade happens
                    # immediately, current plan is ended. The only link we have to the current
                    # plan is the original transaction ID, so we use that to cancel the old
                    # payment and issue a new one.
                    with base.SQLTransaction(sql_conn) as sql_tx:
                        sql_tx.cancel = True
                        refunded = backend.refund_apple_payment(tx                   = sql_tx,
                                                                apple_original_tx_id = tx.originalTransactionId,
                                                                refund_unix_ts_ms    = tx.purchaseDate)
                        if not refunded:
                            err.msg_list.append(f'No matching active payment was available to be refunded. {print_obj(tx)}')

                        # NOTE: Submit the 'new' payment
                        if not err.has():
                            backend.add_unredeemed_payment_tx(tx                                = sql_tx,
                                                              payment_tx                        = payment_tx,
                                                              plan                              = pro_plan,
                                                              expiry_unix_ts_ms                 = tx.expiresDate,
                                                              unredeemed_unix_ts_ms             = tx.purchaseDate,
                                                              platform_refund_expiry_unix_ts_ms = 0, # TODO
                                                              err                               = err)

                        if not err.has():
                            _ = backend.update_payment_renewal_info_tx(tx                       = sql_tx,
                                                                       payment_tx               = payment_tx,
                                                                       grace_period_duration_ms = GRACE_PERIOD_DURATION_MS,
                                                                       auto_renewing            = True,
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
            _ = require_field(tx.purchaseDate,          f'{decoded_notification.body.notificationType} is missing TX purchase date. {print_obj(tx)}',           err)
            _ = require_field(tx.originalTransactionId, f'{decoded_notification.body.notificationType} is missing TX original transaction ID. {print_obj(tx)}', err)
        else:
            err.msg_list.append(f'{decoded_notification.body.notificationType} is missing TX info {print_obj(tx)}')

        if len(err.msg_list) == 0:
            assert tx # NOTE: Assert the types for LSP now that we have checked that they exist
            assert isinstance(tx.purchaseDate,          int), f'{print_obj(tx)}'
            assert isinstance(tx.originalTransactionId, str), f'{print_obj(tx)}'

            # NOTE: Process
            with base.SQLTransaction(sql_conn) as sql_tx:
                sql_tx.cancel = not backend.refund_apple_payment(tx                   = sql_tx,
                                                                 apple_original_tx_id = tx.originalTransactionId,
                                                                 refund_unix_ts_ms    = tx.purchaseDate)
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
            _ = require_field(tx.expiresDate,           f'{decoded_notification.body.notificationType} is missing TX expires date. {print_obj(tx)}',            err)
            _ = require_field(tx.originalTransactionId, f'{decoded_notification.body.notificationType} is missing TX original transaction ID. {print_obj(tx)}', err)
            _ = require_field(tx.transactionId,         f'{decoded_notification.body.notificationType} is missing TX transaction ID. {print_obj(tx)}',          err)
            _ = require_field(tx.transactionReason,     f'{decoded_notification.body.notificationType} is missing TX reason. {print_obj(tx)}',                  err)
            _ = require_field(tx.type,                  f'{decoded_notification.body.notificationType} is missing TX type. {print_obj(tx)}',                    err)
        else:
            err.msg_list.append(f'{decoded_notification.body.notificationType} is missing TX info {print_obj(tx)}')

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
            err.msg_list.append(f'{decoded_notification.body.notificationType} is missing TX info {print_obj(tx)}')

        if not decoded_notification.body.subtype == AppleSubtype.AUTO_RENEW_DISABLED and not decoded_notification.body.subtype == AppleSubtype.AUTO_RENEW_ENABLED:
            err.msg_list.append(f'Received TX: {print_obj(tx)}, with unrecognised subtype for a DID_CHANGE_RENEWAL_STATUS notification')

        if not err.has():
            assert tx
            payment_tx: backend.PaymentProviderTransaction = payment_tx_from_apple_jws_transaction(tx, err)
            if not err.has():
                auto_renewing: bool = decoded_notification.body.subtype == AppleSubtype.AUTO_RENEW_ENABLED
                _ = backend.update_payment_renewal_info(sql_conn                 = sql_conn,
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
            err.msg_list.append(f'{decoded_notification.body.notificationType} is missing renewal info {print_obj(renewal)}')
        if not tx:
            err.msg_list.append(f'{decoded_notification.body.notificationType} is missing TX info {print_obj(tx)}')

        if not err.has():
            assert renewal
            _ = require_field(renewal.gracePeriodExpiresDate, f'{decoded_notification.body.notificationType} is missing renewal grace period expires date. {print_obj(renewal)}', err)

        if not err.has():
            assert renewal
            assert tx
            payment_tx: backend.PaymentProviderTransaction = payment_tx_from_apple_jws_transaction(tx, err)
            if not err.has():
                if not decoded_notification.body.subtype:
                    pass
                elif decoded_notification.body.subtype == AppleSubtype.GRACE_PERIOD:
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

        tx = decoded_notification.tx_info
        if not tx:
            err.msg_list.append(f'{decoded_notification.body.notificationType} is missing TX info {print_obj(tx)}')

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
            # NOTE: No-op, the user is still entitled to Session Pro
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
            # TODO: No-op, the Session Pro proofs have an expiry date embedded into them and that is
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
            # TODO: No-op, the apps do not respond to price increases
            pass


    # NOTE: Erroneous cases, scenarios we don't support/should never receive a notification for
    elif decoded_notification.body.notificationType == AppleNotificationV2.EXTERNAL_PURCHASE_TOKEN or \
         decoded_notification.body.notificationType == AppleNotificationV2.RENEWAL_EXTENDED        or \
         decoded_notification.body.notificationType == AppleNotificationV2.RENEWAL_EXTENSION:

         if decoded_notification.body.notificationType == AppleNotificationV2.EXTERNAL_PURCHASE_TOKEN:
            err.msg_list.append(f'Received Apple notification "{decoded_notification.body.notificationType}", but we do not support 3rd party stores through Apple')
         elif decoded_notification.body.notificationType == AppleNotificationV2.RENEWAL_EXTENSION or decoded_notification.body.notificationType == AppleNotificationV2.RENEWAL_EXTENDED:
            err.msg_list.append(f'Received Apple notification "{decoded_notification.body.notificationType}", but we don\'t handle issueing the extension of a subscription renewal (e.g.: to compensate for service outages)')
    else:
        err.msg_list.append(f'Received Apple notification {decoded_notification.body.notificationType} that wasn\'t explicitly handled')

    if len(err.msg_list):
        err_msg = '\n'.join(err.msg_list)
        print(f'ERROR: {err_msg}\nPayload was: {print_obj(decoded_notification.body)}')


@flask_blueprint.route(FLASK_ROUTE_NOTIFICATIONS_APPLE_APP_CONNECT_SANDBOX, methods=['POST'])
def notifications_apple_app_connect_sandbox() -> flask.Response:
    get: server.GetJSONFromFlaskRequest = server.get_json_from_flask_request(flask.request)
    if len(get.err_msg):
        print(f'Failed to parse Apple notification as JSON: {flask.request.data}')
        flask.abort(500)

    print(f'Received Apple notification: {json.dumps(get.json, indent=1)}')
    with open('sesh_pro_backend_debug.log', 'a') as file:
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        _ = file.write(f'{ts}: Received Apple notification: {get.json}\n')

    assert isinstance(get.json, dict)
    assert FLASK_CONFIG_PLATFORM_APPLE_CORE_KEY in flask.current_app.config
    assert isinstance(flask.current_app.config[FLASK_CONFIG_PLATFORM_APPLE_CORE_KEY], Core)
    core = typing.cast(Core, flask.current_app.config[FLASK_CONFIG_PLATFORM_APPLE_CORE_KEY])

    if 'signedPayload' not in get.json:
        print(f'Failed to parse Apple notification, signedPayload key was missing: {base.safe_dump_dict_keys_or_data(get.json)}')
        flask.abort(500)

    signed_payload = get.json['signedPayload']
    if not isinstance(signed_payload, str):
        print(f'Failed to parse Apple notification, signed payload was not a string: {type(signed_payload)}')
        flask.abort(500)

    resp = core.signed_data_verifier.verify_and_decode_notification(signed_payload)
    with open('sesh_pro_backend_debug.log', 'a') as file:
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        _ = file.write(f'{ts}: Decoded Apple notification: {resp}\n')

    flask.abort(500)

def trigger_test_notification(client: AppleAppStoreServerAPIClient, verifier: AppleSignedDataVerifier):
    try:
        response_test_notif: AppleSendTestNotificationResponse = client.request_test_notification()
        print('Send test notif: ', response_test_notif)

        notification_token = response_test_notif.testNotificationToken
        if notification_token:
            response_check_test_notif: AppleCheckTestNotificationResponse = client.get_test_notification_status(test_notification_token=notification_token)
            print('Check test notif: ', response_check_test_notif)
            if response_check_test_notif.signedPayload:
                decoded_response: AppleResponseBodyV2DecodedPayload = verifier.verify_and_decode_notification(signed_payload=response_check_test_notif.signedPayload)
                print('Decoded test response: ', decoded_response)
    except AppleAPIException as e:
        print(e)

def init() -> Core:
    # NOTE: Enforce the presence of platform_config.py and the variables required for Apple
    # integration
    try:
        import platform_config
        import_error = False
        if not hasattr(platform_config, 'apple_key_id') or not isinstance(platform_config.apple_key_id, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            print('ERROR: Missing "apple_key_id" string in platform_config.py')
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

    # NOTE: For version 2 notifications, it retries five times, at 1, 12, 24, 48, and 72 hours after the previous attempt.
    #
    #   https://developer.apple.com/documentation/appstoreservernotifications/responding-to-app-store-server-notifications

    app_apple_id: int | None = None
    apple_env                = AppleEnvironment.SANDBOX
    if apple_env != AppleEnvironment.SANDBOX:
        assert app_apple_id is not None, 'App ID must be set in a non-sandbox environment'

    app_store_server_api_client = AppleAppStoreServerAPIClient(signing_key=platform_config.apple_key_bytes,
                                                               key_id=platform_config.apple_key_id,
                                                               issuer_id=platform_config.apple_issuer_id,
                                                               bundle_id=platform_config.apple_bundle_id,
                                                               environment=apple_env)
    signed_data_verifier        = AppleSignedDataVerifier     (root_certificates=platform_config.apple_root_certs,
                                                               enable_online_checks=True,
                                                               environment=apple_env,
                                                               bundle_id=platform_config.apple_bundle_id,
                                                               app_apple_id=app_apple_id)

    result = Core(app_store_server_api_client, signed_data_verifier)
    return result

def equip_flask_routes(core: Core, flask: flask.Flask):
    flask.register_blueprint(flask_blueprint)

    # NOTE: Add the core data structure for Apple into the flask config dictionary. This makes it
    # accessible in routes across concurrent connections.
    flask.config[FLASK_CONFIG_PLATFORM_APPLE_CORE_KEY] = core

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
