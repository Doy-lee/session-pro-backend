import json
import sys
import typing
from enum import IntEnum, StrEnum

from google.cloud import pubsub_v1
import google.cloud.pubsub_v1.subscriber.message

import base
from base import json_dict_require_str, json_dict_require_int


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
        event_time_millis_str = json_dict_require_str(body, "eventTimeMillis", err)

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
                            subscription_notification_type_str = json_dict_require_str(subscription, "notificationType", err)
                            purchase_token = json_dict_require_str(subscription, "purchaseToken", err)

                            subscription_notification_type = None
                            try:
                                subscription_notification_type = int(subscription_notification_type_str)
                            except Exception as e:
                                err.msg_list.append(f'Unable to parse subscription notification type to an int: {subscription_notification_type_str} {e}')

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
                                    err.msg_list.append(f'{NotificationType.SUBSCRIPTION} notificationType is invalid: {subscription_notification_type_str}')

                        else:
                            err.msg_list.append(f'{NotificationType.SUBSCRIPTION} data is not valid!')

                    case NotificationType.VOIDED_PURCHASE:
                        voided_purchase = body[NotificationType.VOIDED_PURCHASE]

                        if isinstance(voided_purchase, dict):
                            purchase_token = json_dict_require_str(voided_purchase, "purchaseToken", err)
                            order_id = json_dict_require_str(voided_purchase, "orderId", err)
                            product_type_str = json_dict_require_str(voided_purchase, "productType", err)
                            raw_refund_type_str = json_dict_require_str(voided_purchase, "refundType", err)

                            product_type = None
                            try:
                                product_type = int(product_type_str)
                            except Exception as e:
                                err.msg_list.append(f'Unable to parse product type to an int: {product_type_str} {e}')

                            raw_refund_type = None
                            try:
                                raw_refund_type = int(raw_refund_type_str)
                            except Exception as e:
                                err.msg_list.append(f'Unable to parse refund type to an int: {raw_refund_type_str} {e}')

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
                        print(f'{NotificationType.TEST} payload was: {json.dumps(body, indent=1)}')

                    case _:
                        err.msg_list.append(f'{notification_type} is not a valid notification type!')
        else:
            err.msg_list.append(f'{package_name} does not match google_package_name from the config!')

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
        handle_notification(body, err)
    else:
        err.msg_list.append("Message data is not a valid JSON object")

    if len(err.msg_list) > 0:
        err_msg = '\n'.join(err.msg_list)
        print(f'ERROR: {err_msg}\nPayload was: {json.dumps(body, indent=1)}')
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
