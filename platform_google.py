import json
import os
import sys
import typing
from enum import IntEnum, StrEnum

from google.cloud import pubsub_v1
import google.cloud.pubsub_v1.subscriber.message

import base
from base import json_dict_require_str, json_dict_require_str_coerce_to_int, safe_dump_dict_keys_or_data

from env import env

from googleapiclient.discovery import build
from google.oauth2 import service_account

SCOPES = ['https://www.googleapis.com/auth/androidpublisher']

def create_service():
    """Create and return the Android Publisher service object using environment credentials."""
    # Get the service account file path from environment variable
    if not os.path.exists(env.GOOGLE_APPLICATION_CREDENTIALS):
        raise FileNotFoundError(f"Service account file not found: {env.GOOGLE_APPLICATION_CREDENTIALS}")

    credentials = service_account.Credentials.from_service_account_file(
        env.GOOGLE_APPLICATION_CREDENTIALS, scopes=SCOPES)

    service = build('androidpublisher', 'v3', credentials=credentials)
    return service

def get_subscription_v2(package_name: str, token: str, err: base.ErrorSink):
    """
    Call the purchases.subscriptionsv2.get endpoint.

    Args:
        package_name (str): The package name of your app
        token (str): The purchase token for the subscription
        err (base.ErrorSink): The error sink

    Returns:
        dict: The subscription details
    """
    service = create_service()

    try:
        result = service.purchases().subscriptionsv2().get(
            packageName=package_name,
            token=token
        ).execute()

        if isinstance(result, dict):
            if "subscribeWithGoogleInfo" in result:
                del result["subscribeWithGoogleInfo"]

            kind = json_dict_require_str(result, "kind", err)
            if kind != "androidpublisher#subscriptionPurchaseV2":
                err.msg_list.append(f'purchases.subscriptionsv2.get has incorrect kind: {kind}')
        else:
            err.msg_list.append('Failed to get subscription details, result not a dict')

        if len(err.msg_list) > 0:
            return None

        return result

    except Exception as e:
        err.msg_list.append(f'Failed to get subscription details: {e}')
        return None

class SubscriptionNotificationType(IntEnum):
    """Subscription notification types as per Google Play documentation"""
    # A subscription was recovered from account hold.
    SUBSCRIPTION_RECOVERED = 1
    # An active subscription was renewed.
    SUBSCRIPTION_RENEWED = 2
    # A subscription was either voluntarily or involuntarily cancelled. For voluntary cancellation, sent when the user cancels.
    SUBSCRIPTION_CANCELED = 3
    # A new subscription was purchased.
    SUBSCRIPTION_PURCHASED = 4
    # A subscription has entered account hold (if enabled).
    SUBSCRIPTION_ON_HOLD = 5
    # A subscription has entered grace period (if enabled).
    SUBSCRIPTION_IN_GRACE_PERIOD = 6
    # User has restored their subscription from Play > Account > Subscriptions. The subscription was canceled but had not expired yet when the user restores. For more information, see Restorations.
    SUBSCRIPTION_RESTARTED = 7
    # @deprecated A subscription price change has successfully been confirmed by the user.
    SUBSCRIPTION_PRICE_CHANGE_CONFIRMED = 8
    # A subscription's recurrence time has been extended.
    SUBSCRIPTION_DEFERRED = 9
    # A subscription has been paused.
    SUBSCRIPTION_PAUSED = 10
    # A subscription pause schedule has been changed.
    SUBSCRIPTION_PAUSE_SCHEDULE_CHANGED = 11
    # A subscription has been revoked from the user before the expiration time.
    SUBSCRIPTION_REVOKED = 12
    # A subscription has expired.
    SUBSCRIPTION_EXPIRED = 13
    # A subscription item's price change details are updated.
    SUBSCRIPTION_PRICE_CHANGE_UPDATED = 19
    # A pending transaction of a subscription has been canceled.
    SUBSCRIPTION_PENDING_PURCHASE_CANCELED = 20
    # A subscription's consent period for price step-up has begun or the user has provided consent for the price step-up. This RTDN is sent only for subscriptions in a region where price step-up is required.
    SUBSCRIPTION_PRICE_STEP_UP_CONSENT_UPDATED = 22


class ProductType(IntEnum):
    """Product types for voided purchases"""
    # A subscription purchase has been voided.
    PRODUCT_TYPE_SUBSCRIPTION = 1
    # A one-time purchase has been voided.
    PRODUCT_TYPE_ONE_TIME = 2


class RefundType(IntEnum):
    """Refund types for voided purchases"""
    # The purchase has been fully voided.
    REFUND_TYPE_FULL_REFUND = 1
    # The purchase has been partially voided by a quantity-based partial refund, applicable only to multi-quantity purchases. A purchase can be partially voided multiple times.
    REFUND_TYPE_QUANTITY_BASED_PARTIAL_REFUND = 2

class NotificationType(StrEnum):
    """Notification types for RTDN notifications. These are the keys."""
    # If this field is present, then this notification is related to a subscription, and this field contains additional information related to the subscription. Note that this field is mutually exclusive with oneTimeProductNotification, voidedPurchaseNotification, and testNotification.
    SUBSCRIPTION = "subscriptionNotification"
    # If this field is present, then this notification is related to a one-time purchase, and this field contains additional information related to the purchase. Note that this field is mutually exclusive with subscriptionNotification, voidedPurchaseNotification, and testNotification.
    ONE_TIME_PRODUCT = "oneTimeProductNotification"
    # If this field is present, then this notification is related to a voided purchase, and this field contains additional information related to the voided purchase. Note that this field is mutually exclusive with oneTimeProductNotification, subscriptionNotification, and testNotification.
    VOIDED_PURCHASE = "voidedPurchaseNotification"
    # If this field is present, then this notification is related to a test publish. These are sent only through the Google Play Developer Console. Note that this field is mutually exclusive with oneTimeProductNotification, subscriptionNotification, and voidedPurchaseNotification.
    TEST = "testNotification"

class SubscriptionsV2SubscriptionStateType(StrEnum):
    """Subscriptions V2 subscription state types"""
    # Unspecified subscription state.
    SUBSCRIPTION_STATE_UNSPECIFIED = "SUBSCRIPTION_STATE_UNSPECIFIED"
    # Subscription was created but awaiting payment during signup. In this state, all items are awaiting payment.
    SUBSCRIPTION_STATE_PENDING = "SUBSCRIPTION_STATE_PENDING"
    # Subscription is active. - (1) If the subscription is an auto renewing plan, at least one item is autoRenewEnabled and not expired. - (2) If the subscription is a prepaid plan, at least one item is not expired.
    SUBSCRIPTION_STATE_ACTIVE ="SUBSCRIPTION_STATE_ACTIVE"
    # Subscription is paused. The state is only available when the subscription is an auto renewing plan. In this state, all items are in paused state.
    SUBSCRIPTION_STATE_PAUSED = "SUBSCRIPTION_STATE_PAUSED"
    # Subscription is in grace period. The state is only available when the subscription is an auto renewing plan. In this state, all items are in grace period.
    SUBSCRIPTION_STATE_IN_GRACE_PERIOD = "SUBSCRIPTION_STATE_IN_GRACE_PERIOD"
    # Subscription is on hold (suspended). The state is only available when the subscription is an auto renewing plan. In this state, all items are on hold.
    SUBSCRIPTION_STATE_ON_HOLD ="SUBSCRIPTION_STATE_ON_HOLD"
    # Subscription is canceled but not expired yet. The state is only available when the subscription is an auto renewing plan. All items have autoRenewEnabled set to false.
    SUBSCRIPTION_STATE_CANCELED ="SUBSCRIPTION_STATE_CANCELED"
    # Subscription is expired. All items have expiryTime in the past.
    SUBSCRIPTION_STATE_EXPIRED ="SUBSCRIPTION_STATE_EXPIRED"
    # Pending transaction for subscription is canceled. If this pending purchase was for an existing subscription, use linkedPurchaseToken to get the current state of that subscription.
    SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED ="SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED"

class SubscriptionsV2SubscriptionAcknowledgementStateType(StrEnum):
    """Subscriptions V2 subscription Acknowledgement state types"""
    # Unspecified acknowledgement state.
    ACKNOWLEDGEMENT_STATE_UNSPECIFIED = "ACKNOWLEDGEMENT_STATE_UNSPECIFIED"
    # The subscription is not acknowledged yet.
    ACKNOWLEDGEMENT_STATE_PENDING = "ACKNOWLEDGEMENT_STATE_PENDING"
    # The subscription is acknowledged.
    ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED = "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED"

def require_field(field: typing.Any, msg: str, err: base.ErrorSink | None) -> bool:
    result = True
    if field is None:
        result = False
        if err:
            err.msg_list.append(msg)
    return result

def handle_subscription_refund(purchaseToken: str):
    raise NotImplementedError("handle_subscription_refund is not implemented yet!")

def handle_notification(body:dict, err: base.ErrorSink):
        body_version = json_dict_require_str(body, "version", err)
        package_name = json_dict_require_str(body, "packageName", err)
        event_time_millis = json_dict_require_str_coerce_to_int(body, "eventTimeMillis", err)

        if len(err.msg_list) > 0:
            return

        if package_name == platform_config.google_package_name:
            notification_type: NotificationType | None = None
            keys = body.keys()
            for key in keys:
                if key == "subscriptionNotification":
                    if notification_type is None:
                        notification_type = NotificationType.SUBSCRIPTION
                    else:
                        err.msg_list.append(f'body contains multiple notification types: {keys}')

                elif key == "oneTimeProductNotification":
                    if notification_type is None:
                        notification_type = NotificationType.ONE_TIME_PRODUCT
                    else:
                        err.msg_list.append(f'body contains multiple notification types: {keys}')

                elif key == "voidedPurchaseNotification":
                    if notification_type is None:
                        notification_type = NotificationType.VOIDED_PURCHASE
                    else:
                        err.msg_list.append(f'body contains multiple notification types: {keys}')

                elif key == "testNotification":
                    if notification_type is None:
                        notification_type = NotificationType.TEST
                    else:
                        err.msg_list.append(f'body contains multiple notification types: {keys}')

            if notification_type is None:
                err.msg_list.append(f'body contains no notification type: {keys}')
            else:
                match notification_type:
                    case NotificationType.SUBSCRIPTION:
                        subscription = body[NotificationType.SUBSCRIPTION]
                        if isinstance(subscription, dict):
                            version = json_dict_require_str(subscription, "version",  err)
                            subscription_notification_type = json_dict_require_str_coerce_to_int(subscription, "notificationType", err)
                            purchase_token = json_dict_require_str(subscription, "purchaseToken", err)

                            if len(err.msg_list) > 0:
                                return

                            match subscription_notification_type:
                                case SubscriptionNotificationType.SUBSCRIPTION_RECOVERED:
                                    raise NotImplementedError()
                                case SubscriptionNotificationType.SUBSCRIPTION_RENEWED:
                                    raise NotImplementedError()
                                case SubscriptionNotificationType.SUBSCRIPTION_CANCELED:
                                    raise NotImplementedError()
                                case SubscriptionNotificationType.SUBSCRIPTION_PURCHASED:
                                    details = get_subscription_v2(package_name, purchase_token, err)

                                    if len(err.msg_list) > 0 or details is None:
                                        return

                                    acknowledgement_state = json_dict_require_str(details, "acknowledgementState", err)
                                    if acknowledgement_state == SubscriptionsV2SubscriptionAcknowledgementStateType.ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED:
                                        err.msg_list.append(f'Message is already acknowledged')

                                    subscription_state = json_dict_require_str(details, "subscriptionState", err)
                                    start_time_str = json_dict_require_str(details, "startTime", err)

                                    linked_purchase_token = None
                                    if 'linkedPurchaseToken' in details:
                                        linked_purchase_token = json_dict_require_str(details, "linkedPurchaseToken", err)

                                    # TODO: if linked_purchase_token exits we need to revoke the old subscription proof

                                    test_purchase = None
                                    if 'testPurchase' in details:
                                        test_purchase = json_dict_require_str(details, "testPurchase", err)
                                        print(test_purchase)

                                    if len(err.msg_list) > 0:
                                        return

                                    # match subscription_state:
                                    #     case SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_UNSPECIFIED:
                                    #         subscription_state = SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_UNSPECIFIED
                                    #     case SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_PENDING:




                                    raise NotImplementedError()
                                case SubscriptionNotificationType.SUBSCRIPTION_ON_HOLD:
                                    raise NotImplementedError()
                                case SubscriptionNotificationType.SUBSCRIPTION_IN_GRACE_PERIOD:
                                    raise NotImplementedError()
                                case SubscriptionNotificationType.SUBSCRIPTION_RESTARTED:
                                    raise NotImplementedError()
                                case SubscriptionNotificationType.SUBSCRIPTION_PRICE_CHANGE_CONFIRMED:
                                    raise NotImplementedError()
                                case SubscriptionNotificationType.SUBSCRIPTION_DEFERRED:
                                    err.msg_list.append(f'{NotificationType.SUBSCRIPTION} notificationType SUBSCRIPTION_DEFERRED ({SubscriptionNotificationType.SUBSCRIPTION_DEFERRED}) is unsupported!')
                                case SubscriptionNotificationType.SUBSCRIPTION_PAUSED:
                                    raise NotImplementedError()
                                case SubscriptionNotificationType.SUBSCRIPTION_PAUSE_SCHEDULE_CHANGED:
                                    raise NotImplementedError()
                                case SubscriptionNotificationType.SUBSCRIPTION_REVOKED:
                                    raise NotImplementedError()
                                case SubscriptionNotificationType.SUBSCRIPTION_EXPIRED:
                                    raise NotImplementedError()
                                case SubscriptionNotificationType.SUBSCRIPTION_PRICE_CHANGE_UPDATED:
                                    raise NotImplementedError()
                                case SubscriptionNotificationType.SUBSCRIPTION_PENDING_PURCHASE_CANCELED:
                                    raise NotImplementedError()
                                case SubscriptionNotificationType.SUBSCRIPTION_PRICE_STEP_UP_CONSENT_UPDATED:
                                    raise NotImplementedError()
                                case _:
                                    err.msg_list.append(f'{NotificationType.SUBSCRIPTION} notificationType is invalid: {subscription_notification_type}')

                        else:
                            err.msg_list.append(f'{NotificationType.SUBSCRIPTION} data is not valid!')

                    case NotificationType.VOIDED_PURCHASE:
                        voided_purchase = body[NotificationType.VOIDED_PURCHASE]

                        if isinstance(voided_purchase, dict):
                            purchase_token = json_dict_require_str(voided_purchase, "purchaseToken", err)
                            order_id = json_dict_require_str(voided_purchase, "orderId", err)
                            product_type = json_dict_require_str_coerce_to_int(voided_purchase, "productType", err)
                            raw_refund_type = json_dict_require_str_coerce_to_int(voided_purchase, "refundType", err)

                            if len(err.msg_list) > 0:
                                return

                            refund_type: RefundType | None = None
                            match raw_refund_type:
                                case RefundType.REFUND_TYPE_FULL_REFUND:
                                    refund_type = RefundType.REFUND_TYPE_FULL_REFUND
                                case RefundType.REFUND_TYPE_QUANTITY_BASED_PARTIAL_REFUND:
                                    refund_type = RefundType.REFUND_TYPE_QUANTITY_BASED_PARTIAL_REFUND

                            if refund_type is None:
                                err.msg_list.append(f'{NotificationType.VOIDED_PURCHASE} refundType is None!')
                            else:
                                match product_type:
                                    case ProductType.PRODUCT_TYPE_SUBSCRIPTION:
                                        match refund_type:
                                            case RefundType.REFUND_TYPE_FULL_REFUND:
                                                handle_subscription_refund(purchase_token)
                                            case RefundType.REFUND_TYPE_QUANTITY_BASED_PARTIAL_REFUND:
                                                # TODO: we need to check if this is actually unsupported, as far as a i can tell it doesnt relate to subscriptions
                                                err.msg_list.append(f'{NotificationType.VOIDED_PURCHASE} refundType REFUND_TYPE_QUANTITY_BASED_PARTIAL_REFUND ({RefundType.REFUND_TYPE_QUANTITY_BASED_PARTIAL_REFUND}) is unsupported!')
                                            case _:
                                                err.msg_list.append(f'{NotificationType.VOIDED_PURCHASE} refundType is not valid!')
                                    case ProductType.PRODUCT_TYPE_ONE_TIME:
                                        err.msg_list.append(f'{NotificationType.VOIDED_PURCHASE} productType PRODUCT_TYPE_ONE_TIME ({ProductType.PRODUCT_TYPE_ONE_TIME}) is unsupported!')
                                    case _:
                                        err.msg_list.append(f'{NotificationType.VOIDED_PURCHASE} productType is not valid!')

                    case NotificationType.ONE_TIME_PRODUCT:
                        err.msg_list.append(f'{NotificationType.ONE_TIME_PRODUCT} is not supported!')

                    case NotificationType.TEST:
                        print(f'{NotificationType.TEST} payload was: {safe_dump_dict_keys_or_data(body)}')

                    case _:
                        err.msg_list.append(f'{notification_type} is not a valid notification type!')
        else:
            err.msg_list.append(f'{package_name} does not match google_package_name ({platform_config.google_package_name}) from the platform_config!')

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
    err            = base.ErrorSink()

    data = None
    try:
        data = message.data
    except Exception as e:
        err.msg_list.append(f'Unable to decode message: {e}')

    body = None
    if data is not None:
        try:
            body = json.loads(message.data)
        except Exception as e:
            err.msg_list.append(f"Failed to parse JSON! {e}")

    if body is not None and isinstance(body, dict):
        if env.SESH_PRO_BACKEND_UNSAFE_LOGGING_VERBOSE:
            print(body)
        handle_notification(body, err)
    else:
        err.msg_list.append("Message data is not a valid JSON object")

    if len(err.msg_list) > 0:
        err_msg = '\n'.join(err.msg_list)
        print(f'ERROR: {err_msg}\nPayload was: {safe_dump_dict_keys_or_data(body)}')
    else:
        print('ACK')
        message.ack()

with pubsub_v1.SubscriberClient() as sub_client:
    sub_path = sub_client.subscription_path(project='loki-5a81e', subscription='session-pro-sub')
    future = sub_client.subscribe(subscription=sub_path, callback=callback)
    try:
        future.result()
    except KeyboardInterrupt:
        future.cancel()  # Trigger the shutdown.
        future.result()  # Block until the shutdown is complete.
