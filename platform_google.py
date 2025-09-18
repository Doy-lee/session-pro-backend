import json
import sys
import typing

from google.cloud import pubsub_v1
import google.cloud.pubsub_v1.subscriber.message
from google.protobuf.internal.well_known_types import Timestamp

import base
from base import json_dict_require_str, json_dict_require_int, json_dict_require_str_coerce_to_int, \
    safe_dump_dict_keys_or_data, json_dict_require_obj, json_dict_require_array, json_dict_require_bool

import env

from googleapiclient.discovery import build
from google.oauth2 import service_account

from platform_google_types import NotificationType, SubscriptionNotificationType, \
    SubscriptionsV2SubscriptionAcknowledgementStateType, RefundType, ProductType, SubscriptionV2Data, GoogleTimestamp, \
    SubscriptionV2DataOfferDetails, GoogleMoney, SubscriptionV2SubscriptionItemPriceChangeDetails, \
    SubscriptionV2SubscriptionItemPriceChangeDetailsModeType, SubscriptionV2SubscriptionItemPriceChangeDetailsStateType, \
    SubscriptionV2DataAutoRenewingPlan, SubscriptionV2SubscriptionPriceConsentStateType, json_dict_require_google_money, \
    json_dict_require_google_timestamp, SubscriptionV2SubscriptionItemInstallmentPlanPendingCancellation, \
    SubscriptionV2SubscriptionItemInstallmentPlan, SubscriptionV2DataLineItem, SubscriptionsV2SubscriptionStateType, \
    SubscriptionsV2SubscriptionPausedStateContext

SCOPES = ['https://www.googleapis.com/auth/androidpublisher']

def create_service():
    """Create and return the Android Publisher service object using environment credentials."""
    # Get the service account file path from environment variable
    credentials = service_account.Credentials.from_service_account_file(
        env.GOOGLE_APPLICATION_CREDENTIALS, scopes=SCOPES)

    service = build('androidpublisher', 'v3', credentials=credentials)
    return service

def get_subscription_v2(package_name: str, token: str, err: base.ErrorSink) -> SubscriptionV2Data:
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
    result = None
    try:
        response = service.purchases().subscriptionsv2().get(
            packageName=package_name,
            token=token
        ).execute()

        if isinstance(response, dict):
            has_subscribe_with_google_info = False
            has_linked_purchase_token = False
            has_paused_state_context = False
            has_canceled_state_context = False
            has_test_purchase = False

            for key in response.keys():
                match key:
                    case "subscribeWithGoogleInfo":
                        has_subscribe_with_google_info = True
                    case "linkedPurchaseToken":
                        has_linked_purchase_token = True
                    case "canceledStateContext":
                        has_canceled_state_context = True
                    case "testPurchase":
                        has_test_purchase = True

            # Delete known PII just in case something logs somewhere
            if has_subscribe_with_google_info:
                del response["subscribeWithGoogleInfo"]

            kind = json_dict_require_str(response, "kind", err)
            if kind != "androidpublisher#subscriptionPurchaseV2":
                err.msg_list.append(f'purchases.subscriptionsv2.get has incorrect kind: {kind}')

            if len(err.msg_list) > 0:
                return result

            line_items_arr = json_dict_require_array(response, "lineItems", err)

            line_items = []
            if len(line_items_arr) == 0:
                err.msg_list.append(f'purchases.subscriptionsv2.get has no lineItems')
            else:
                for line_item in line_items_arr:
                    assert isinstance(line_item, dict)
                    product_id = json_dict_require_str(line_item, "productId", err)
                    expiry_time = json_dict_require_google_timestamp(line_item, "expiryTime", err)

                    if len(err.msg_list) > 0:
                        continue

                    offer_details_obj = json_dict_require_obj(line_item, "offerDetails", err)

                    if len(err.msg_list) > 0:
                        continue

                    offer_details_offer_tags = json_dict_require_array(offer_details_obj, "offerTags", err)
                    offer_details_base_plan_id = json_dict_require_str(offer_details_obj, "basePlanId", err)
                    # TODO: do we want this pattern? how should we handle optionals?
                    offer_details_offer_id = json_dict_require_str(offer_details_obj, "offerId", err) if "offerId" in offer_details_obj else None

                    if len(err.msg_list) > 0:
                        continue

                    offer_details = SubscriptionV2DataOfferDetails(
                        offer_tags=offer_details_offer_tags,
                        base_plan_id=offer_details_base_plan_id,
                        offer_id=offer_details_offer_id,
                    )

                    has_latest_successful_order_id = False

                    # Can either be auto-renewing or prepaid
                    is_auto_renewing_plan = False
                    is_prepaid_plan = False

                    # Only one of these should be true, but all three can be false
                    is_deferred_replacement = False
                    is_deferred_removal = False
                    is_signup_promo = False

                    for key in line_item.keys():
                        match key:
                            case "autoRenewingPlan":
                                is_auto_renewing_plan = True
                            case "prepaidPlan":
                               is_prepaid_plan = True
                            case "deferredItemReplacement":
                                is_deferred_replacement = True
                            case "deferredItemRemoval":
                                is_deferred_removal = True
                            case "signupPromotion":
                                is_signup_promo = True
                            case "latestSuccessfulOrderId":
                                has_latest_successful_order_id = True

                    latest_successful_order_id = json_dict_require_str(offer_details_obj, "latestSuccessfulOrderId", err) if has_latest_successful_order_id else None

                    if is_prepaid_plan and is_auto_renewing_plan:
                        err.msg_list.append(f'purchases.subscriptions.get line item has both auto_renewing_plan and prepaid_plan keys! This should never happen!')

                    if sum([is_deferred_replacement, is_deferred_removal, is_signup_promo]) > 1:
                        err.msg_list.append(f'purchases.subscriptions.get line item has more than one of "deferred_item_replacement" ({is_deferred_replacement}), "deferred_item_removal" ({is_deferred_removal}), or "signup_promotion" ({is_signup_promo}) set! This should never happen!')

                    if err.has():
                        continue

                    auto_renewing_plan = None
                    prepaid_plan = None
                    deferred_item_replacement = None
                    deferred_item_removal = None
                    signup_promotion = None

                    if is_auto_renewing_plan:
                        auto_renewing_plan_obj = json_dict_require_obj(line_item, "autoRenewingPlan", err)

                        auto_renew_enabled = json_dict_require_bool(auto_renewing_plan_obj, "autoRenewEnabled", err)

                        recurring_price = json_dict_require_google_money(auto_renewing_plan_obj, "recurringPrice", err)

                        has_price_change_details = False
                        has_installment_details = False
                        has_price_step_up_consent_details = False

                        for key in auto_renewing_plan_obj.keys():
                            match key:
                                case "priceChangeDetails":
                                    has_price_change_details = True
                                case "installmentDetails":
                                    has_installment_details = True
                                case "priceStepUpConsentDetails":
                                    has_price_step_up_consent_details = True


                        price_change_details = None
                        if has_price_change_details:
                            price_change_details_obj = json_dict_require_obj(auto_renewing_plan_obj, "priceChangeDetails", err)

                            if err.has():
                                continue

                            new_price = json_dict_require_google_money(price_change_details_obj, "newPrice", err)

                            price_change_mode_str = json_dict_require_str(price_change_details_obj, "priceChangeMode", err)

                            price_change_mode: SubscriptionV2SubscriptionItemPriceChangeDetailsModeType | None = None
                            match price_change_mode_str:
                                case SubscriptionV2SubscriptionItemPriceChangeDetailsModeType.PRICE_DECREASE \
                                    | SubscriptionV2SubscriptionItemPriceChangeDetailsModeType.PRICE_INCREASE \
                                    | SubscriptionV2SubscriptionItemPriceChangeDetailsModeType.OPT_OUT_PRICE_INCREASE:
                                    price_change_mode = price_change_mode_str
                                case _:
                                    err.msg_list.append(f'Invalid price change mode for line item price details: {price_change_mode_str}')

                            price_change_state_str = json_dict_require_str(price_change_details_obj, "priceChangeState", err)

                            price_change_state: SubscriptionV2SubscriptionItemPriceChangeDetailsStateType | None = None
                            match price_change_state_str:
                                case SubscriptionV2SubscriptionItemPriceChangeDetailsStateType.OUTSTANDING \
                                    | SubscriptionV2SubscriptionItemPriceChangeDetailsStateType.CONFIRMED \
                                    | SubscriptionV2SubscriptionItemPriceChangeDetailsStateType.APPLIED\
                                    | SubscriptionV2SubscriptionItemPriceChangeDetailsStateType.CANCELED:
                                    price_change_state = price_change_state_str
                                case _:
                                    err.msg_list.append(f'Invalid price change state for line item price details: {price_change_state_str}')

                            expected_new_price_charge_time = json_dict_require_google_timestamp(price_change_details_obj, "expectedNewPriceChargeTime", err)

                            if err.has():
                                continue

                            price_change_details = SubscriptionV2SubscriptionItemPriceChangeDetails(
                                new_price=new_price,
                                price_change_mode=price_change_mode,
                                price_change_state=price_change_state,
                                expected_new_price_charge_time=expected_new_price_charge_time,
                            )

                        installment_details = None
                        if has_installment_details:
                            installment_details_obj = json_dict_require_obj(auto_renewing_plan_obj, "installmentDetails", err)

                            if err.has():
                                continue

                            initial_committed_payments_count = json_dict_require_int(installment_details_obj, "initialCommittedPaymentsCount", err)
                            subsequent_committed_payments_count = json_dict_require_int(installment_details_obj, "subsequentCommittedPaymentsCount", err)
                            remaining_committed_payments_count = json_dict_require_int(installment_details_obj, "remainingCommittedPaymentsCount", err)

                            pending_cancellation = None
                            if "pendingCancellation" in installment_details_obj:
                                pending_cancellation_obj = json_dict_require_obj(installment_details_obj, "pendingCancellation", err)
                                pending_cancellation_state_str = json_dict_require_str(pending_cancellation_obj, "state", err)

                                pending_cancellation_state = None
                                match pending_cancellation_state_str:
                                    case SubscriptionV2SubscriptionPriceConsentStateType.CONSENT_STATE_UNSPECIFIED \
                                     | SubscriptionV2SubscriptionPriceConsentStateType.PENDING \
                                     | SubscriptionV2SubscriptionPriceConsentStateType.CONFIRMED \
                                     | SubscriptionV2SubscriptionPriceConsentStateType.COMPLETED:
                                        pending_cancellation_state = pending_cancellation_state_str
                                    case _:
                                        err.msg_list.append(f'Invalid pending cancellation state for auto renew plan installment: {pending_cancellation_state_str}')

                                consent_deadline_time = json_dict_require_google_timestamp(installment_details_obj, "consentDeadlineTime", err)
                                new_price = json_dict_require_google_money(installment_details_obj, "newPrice", err)

                                if err.has() or pending_cancellation_state is None:
                                    continue

                                pending_cancellation = SubscriptionV2SubscriptionItemInstallmentPlanPendingCancellation(
                                    state=pending_cancellation_state,
                                    consent_deadline_time=consent_deadline_time,
                                    new_price=new_price,
                                )

                            if err.has():
                                continue

                            installment_details = SubscriptionV2SubscriptionItemInstallmentPlan(
                                initial_committed_payments_count=initial_committed_payments_count,
                                subsequent_committed_payments_count=subsequent_committed_payments_count,
                                remaining_committed_payments_count=remaining_committed_payments_count,
                                pending_cancellation=pending_cancellation,
                            )

                        price_step_up_consent_details = None
                        if has_price_step_up_consent_details:
                            price_step_up_consent_details_str = json_dict_require_str(auto_renewing_plan_obj, "priceStepUpConsentDetails", err)

                            price_step_up_consent_details: SubscriptionV2SubscriptionPriceConsentStateType | None = None
                            match price_step_up_consent_details_str:
                                case SubscriptionV2SubscriptionPriceConsentStateType.CONSENT_STATE_UNSPECIFIED \
                                    | SubscriptionV2SubscriptionPriceConsentStateType.PENDING \
                                    | SubscriptionV2SubscriptionPriceConsentStateType.CONFIRMED \
                                    | SubscriptionV2SubscriptionPriceConsentStateType.COMPLETED:
                                    price_step_up_consent_details = price_step_up_consent_details_str
                                case _:
                                    err.msg_list.append(f'Invalid price_step_up_consent_details state for auto renew plan: {price_step_up_consent_details}')

                        if err.has():
                            continue

                        auto_renewing_plan = SubscriptionV2DataAutoRenewingPlan(
                            auto_renew_enabled= auto_renew_enabled,
                            recurring_price=recurring_price,
                            price_change_details=price_change_details,
                            installment_details=installment_details,
                            price_step_up_consent_details=price_step_up_consent_details,
                        )

                    elif is_prepaid_plan:
                        handle_not_implemented('prepaidPlan', err)

                    else:
                        err.msg_list.append(f'No plan type in subscription')

                    if err.has():
                        continue

                    # We could probably enforce unique line item types, but this might be overkill. "The items in the same purchase should be either all with AutoRenewingPlan or all with PrepaidPlan."
                    line_items.append(
                        SubscriptionV2DataLineItem(
                            product_id=product_id,
                            expiry_time=expiry_time,
                            latest_successful_order_id=latest_successful_order_id,
                            auto_renewing_plan=auto_renewing_plan,
                            prepaid_plan=prepaid_plan,
                            offer_details=offer_details,
                            deferred_item_replacement=deferred_item_replacement,
                            deferred_item_removal=deferred_item_removal,
                            signup_promotion=signup_promotion,
                        )
                    )

            start_time = json_dict_require_google_timestamp(response, "startTime", err)

            subscription_state_str = json_dict_require_str(response, "subscriptionState", err)

            subscription_state: SubscriptionsV2SubscriptionStateType | None  = None
            match subscription_state_str:
                case SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_UNSPECIFIED \
                     | SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_PENDING \
                     | SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_ACTIVE \
                     | SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_PAUSED \
                     | SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_IN_GRACE_PERIOD \
                     | SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_ON_HOLD \
                     | SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_CANCELED \
                     | SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_EXPIRED \
                     | SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED:
                    subscription_state = subscription_state_str
                case _:
                    err.msg_list.append(f'Invalid subscription state: {subscription_state_str}')


            linked_purchase_token = json_dict_require_str(response, "linkedPurchaseToken", err) if has_linked_purchase_token else None

            paused_state_context = None
            if has_paused_state_context:
                paused_state_context_obj = json_dict_require_obj(response, "pausedStateContext", err)

                if not err.has():
                    auto_resume_time = json_dict_require_google_timestamp(response, "autoResumeTime", err)

                    if not err.has():
                        paused_state_context = SubscriptionsV2SubscriptionPausedStateContext(auto_resume_time=auto_resume_time)

            canceled_state_context = None
            if has_canceled_state_context:
                # TODO: implement
                handle_not_implemented('canceledStateContext', err)

            test_purchase = json_dict_require_obj(response, "testPurchase", err) if has_test_purchase else None

            acknowledgement_state_str = json_dict_require_str(response, "acknowledgementState", err)

            acknowledgement_state: SubscriptionsV2SubscriptionAcknowledgementStateType | None = None
            match acknowledgement_state_str:
                case SubscriptionsV2SubscriptionAcknowledgementStateType.ACKNOWLEDGEMENT_STATE_UNSPECIFIED \
                    | SubscriptionsV2SubscriptionAcknowledgementStateType.ACKNOWLEDGEMENT_STATE_PENDING \
                    | SubscriptionsV2SubscriptionAcknowledgementStateType.ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED:
                    acknowledgement_state = acknowledgement_state_str
                case _:
                    err.msg_list.append(f'Invalid acknowledgement state: {acknowledgement_state_str}')

            if not err.has() and acknowledgement_state is not None:
                result = SubscriptionV2Data(
                    kind=kind,
                    line_items=line_items,
                    start_time=start_time,
                    subscription_state=subscription_state,
                    linked_purchase_token=linked_purchase_token,
                    paused_state_context=paused_state_context,
                    canceled_state_context=canceled_state_context,
                    test_purchase=test_purchase,
                    acknowledgement_state=acknowledgement_state,
                )
        else:
            err.msg_list.append('Failed to get subscription details, result not a dict')

        if len(err.msg_list) > 0:
            return result

        return response

    except Exception as e:
        err.msg_list.append(f'Failed to get subscription details: {e}')
        raise e
        return result

def require_field(field: typing.Any, msg: str, err: base.ErrorSink | None) -> bool:
    result = True
    if field is None:
        result = False
        if err:
            err.msg_list.append(msg)
    return result

def handle_not_implemented(name: str, err: base.ErrorSink):
    err.msg_list.append(f"'{name}' is not implemented!")

def handle_subscription_refund(purchase_token: str, err: base.ErrorSink):
    handle_not_implemented("handle_subscription_refund", err)

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
                            subscription_notification_type = json_dict_require_int(subscription, "notificationType", err)
                            purchase_token = json_dict_require_str(subscription, "purchaseToken", err)

                            if len(err.msg_list) > 0:
                                return

                            match subscription_notification_type:
                                case SubscriptionNotificationType.SUBSCRIPTION_RECOVERED:
                                    handle_not_implemented("SUBSCRIPTION_RECOVERED", err)
                                case SubscriptionNotificationType.SUBSCRIPTION_RENEWED:
                                    handle_not_implemented("SUBSCRIPTION_RENEWED", err)
                                case SubscriptionNotificationType.SUBSCRIPTION_CANCELED:
                                    handle_not_implemented("SUBSCRIPTION_CANCELED", err)
                                case SubscriptionNotificationType.SUBSCRIPTION_PURCHASED:
                                    details = get_subscription_v2(package_name, purchase_token, err)

                                    if len(err.msg_list) > 0 or details is None:
                                        return

                                    acknowledgement_state = json_dict_require_str(details, "acknowledgementState", err)
                                    if acknowledgement_state == SubscriptionsV2SubscriptionAcknowledgementStateType.ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED:
                                        err.msg_list.append(f'Message is already acknowledged')

                                    subscription_state = json_dict_require_str(details, "subscriptionState", err)

                                    # '2025-09-17T05:02:29.546Z'
                                    start_time_str = json_dict_require_str(details, "startTime", err)

                                    linked_purchase_token = None
                                    if 'linkedPurchaseToken' in details:
                                        linked_purchase_token = json_dict_require_str(details, "linkedPurchaseToken", err)

                                    # TODO: if linked_purchase_token exits we need to revoke the old subscription proof

                                    test_purchase = None
                                    if 'testPurchase' in details:
                                        test_purchase = json_dict_require_obj(details, "testPurchase", err)
                                        print(test_purchase)

                                    if len(err.msg_list) > 0:
                                        return

                                    # match subscription_state:
                                    #     case SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_UNSPECIFIED:
                                    #         subscription_state = SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_UNSPECIFIED
                                    #     case SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_PENDING:


                                    handle_not_implemented("SUBSCRIPTION_PURCHASED", err)
                                case SubscriptionNotificationType.SUBSCRIPTION_ON_HOLD:
                                    handle_not_implemented("SUBSCRIPTION_ON_HOLD", err)
                                case SubscriptionNotificationType.SUBSCRIPTION_IN_GRACE_PERIOD:
                                    handle_not_implemented("SUBSCRIPTION_IN_GRACE_PERIOD", err)
                                case SubscriptionNotificationType.SUBSCRIPTION_RESTARTED:
                                    handle_not_implemented("SUBSCRIPTION_RESTARTED", err)
                                case SubscriptionNotificationType.SUBSCRIPTION_PRICE_CHANGE_CONFIRMED:
                                    handle_not_implemented("SUBSCRIPTION_PRICE_CHANGE_CONFIRMED", err)
                                case SubscriptionNotificationType.SUBSCRIPTION_DEFERRED:
                                    err.msg_list.append(f'{NotificationType.SUBSCRIPTION} notificationType SUBSCRIPTION_DEFERRED ({SubscriptionNotificationType.SUBSCRIPTION_DEFERRED}) is unsupported!')
                                case SubscriptionNotificationType.SUBSCRIPTION_PAUSED:
                                    handle_not_implemented("SUBSCRIPTION_PAUSED", err)
                                case SubscriptionNotificationType.SUBSCRIPTION_PAUSE_SCHEDULE_CHANGED:
                                    handle_not_implemented("SUBSCRIPTION_PAUSE_SCHEDULE_CHANGED", err)
                                case SubscriptionNotificationType.SUBSCRIPTION_REVOKED:
                                    handle_not_implemented("SUBSCRIPTION_REVOKED", err)
                                case SubscriptionNotificationType.SUBSCRIPTION_EXPIRED:
                                    handle_not_implemented("SUBSCRIPTION_EXPIRED", err)
                                case SubscriptionNotificationType.SUBSCRIPTION_PRICE_CHANGE_UPDATED:
                                    handle_not_implemented("SUBSCRIPTION_PRICE_CHANGE_UPDATED", err)
                                case SubscriptionNotificationType.SUBSCRIPTION_PENDING_PURCHASE_CANCELED:
                                    handle_not_implemented("SUBSCRIPTION_PENDING_PURCHASE_CANCELED", err)
                                case SubscriptionNotificationType.SUBSCRIPTION_PRICE_STEP_UP_CONSENT_UPDATED:
                                    handle_not_implemented("SUBSCRIPTION_PRICE_STEP_UP_CONSENT_UPDATED", err)
                                case _:
                                    err.msg_list.append(f'{NotificationType.SUBSCRIPTION} notificationType is invalid: {subscription_notification_type}')

                        else:
                            err.msg_list.append(f'{NotificationType.SUBSCRIPTION} data is not valid!')

                    case NotificationType.VOIDED_PURCHASE:
                        voided_purchase = body[NotificationType.VOIDED_PURCHASE]

                        if isinstance(voided_purchase, dict):
                            purchase_token = json_dict_require_str(voided_purchase, "purchaseToken", err)
                            order_id = json_dict_require_str(voided_purchase, "orderId", err)
                            product_type = json_dict_require_int(voided_purchase, "productType", err)
                            raw_refund_type = json_dict_require_int(voided_purchase, "refundType", err)

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
                                                handle_subscription_refund(purchase_token, err)
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
        handle_notification(body, err)
    else:
        err.msg_list.append("Message data is not a valid JSON object")

    if len(err.msg_list) > 0:
        err_msg = '\n'.join(err.msg_list)
        print(f'ERROR: {err_msg}\nPayload was: {safe_dump_dict_keys_or_data(body)}')
    else:
        print('ACK')
        message.ack()

def entry_point():
    with pubsub_v1.SubscriberClient() as sub_client:
        sub_path = sub_client.subscription_path(project='loki-5a81e', subscription='session-pro-sub')
        future = sub_client.subscribe(subscription=sub_path, callback=callback)
        try:
            future.result()
        except KeyboardInterrupt:
            future.cancel()  # Trigger the shutdown.
            future.result()  # Block until the shutdown is complete.

entry_point()