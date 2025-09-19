import json
import logging
import os
import sys
import typing

from google.cloud import pubsub_v1
import google.cloud.pubsub_v1.subscriber.message

import base
from base import json_dict_require_str, json_dict_require_int, json_dict_require_str_coerce_to_int, \
    safe_dump_dict_keys_or_data, json_dict_require_obj, json_dict_require_array, json_dict_require_bool, \
    json_dict_require_str_coerce_to_enum, json_dict_optional_bool, safe_dump_arbitrary_value_or_type, \
    json_dict_optional_str, json_dict_optional_obj, json_dict_require_int_coerce_to_enum

import env

from googleapiclient.discovery import build
from google.oauth2 import service_account

from main import os_get_boolean_env
from platform_google_types import SubscriptionNotificationType, \
    SubscriptionsV2SubscriptionAcknowledgementStateType, RefundType, ProductType, SubscriptionV2Data, GoogleTimestamp, \
    SubscriptionV2DataOfferDetails, GoogleMoney, SubscriptionV2SubscriptionItemPriceChangeDetails, \
    SubscriptionV2SubscriptionItemPriceChangeDetailsModeType, SubscriptionV2SubscriptionItemPriceChangeDetailsStateType, \
    SubscriptionV2DataAutoRenewingPlan, SubscriptionV2SubscriptionPriceConsentStateType, json_dict_require_google_money, \
    json_dict_require_google_timestamp, SubscriptionV2SubscriptionItemInstallmentPlanPendingCancellation, \
    SubscriptionV2SubscriptionItemInstallmentPlan, SubscriptionV2DataLineItem, SubscriptionsV2SubscriptionStateType, \
    SubscriptionsV2SubscriptionPausedStateContext, \
    SubscriptionsV2SubscriptionCanceledStateContextUserSurveyResponseReason, \
    SubscriptionsV2SubscriptionCanceledStateContextUser, \
    SubscriptionsV2SubscriptionCanceledStateContextUserSurveyResponse, SubscriptionsV2SubscriptionCanceledStateContext, \
    json_dict_optional_google_empty_object_bool

SCOPES = ['https://www.googleapis.com/auth/androidpublisher']

def create_service():
    """Create and return the Android Publisher service object using environment credentials."""
    # Get the service account file path from environment variable
    credentials = service_account.Credentials.from_service_account_file(
        env.GOOGLE_APPLICATION_CREDENTIALS, scopes=SCOPES)

    service = build('androidpublisher', 'v3', credentials=credentials)
    return service

def get_subscription_v2(package_name: str, token: str, err: base.ErrorSink) -> SubscriptionV2Data | None:
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
            # Delete known PII just in case something logs somewhere
            if "subscribeWithGoogleInfo" in response:
                del response["subscribeWithGoogleInfo"]

            kind = json_dict_require_str(response, "kind", err)
            if kind != "androidpublisher#subscriptionPurchaseV2":
                err.msg_list.append(f'purchases.subscriptionsv2.get has incorrect kind: {kind}')

            line_items_arr = json_dict_require_array(response, "lineItems", err)
            if len(line_items_arr) == 0:
                err.msg_list.append(f'purchases.subscriptionsv2.get has no lineItems')

            if err.has():
                return result

            line_items = []
            for i in range(len(line_items_arr)):
                line_item = line_items_arr[i]
                if not isinstance(line_item, dict):
                    err.msg_list.append(f'purchases.subscriptionsv2.get line_item at index {i} not a dict: {safe_dump_arbitrary_value_or_type(line_item)}')
                    continue

                product_id = json_dict_require_str(line_item, "productId", err)
                expiry_time = json_dict_require_google_timestamp(line_item, "expiryTime", err)
                offer_details_obj = json_dict_require_obj(line_item, "offerDetails", err)

                offer_details_offer_tags = json_dict_require_array(offer_details_obj, "offerTags", err)
                offer_details_base_plan_id = json_dict_require_str(offer_details_obj, "basePlanId", err)
                offer_details_offer_id = json_dict_optional_str(offer_details_obj, "offerId", err)

                offer_details = SubscriptionV2DataOfferDetails(
                    offer_tags=offer_details_offer_tags,
                    base_plan_id=offer_details_base_plan_id,
                    offer_id=offer_details_offer_id,
                ) if not err.has() else None

                # Can either be auto-renewing or prepaid
                is_auto_renewing_plan = "autoRenewingPlan" in line_item
                is_prepaid_plan = "prepaidPlan" in line_item

                # Only one of these should be true, but all three can be false
                is_deferred_replacement = "deferredItemReplacement" in line_item
                is_deferred_removal = "deferredItemRemoval" in line_item
                is_signup_promo = "signupPromotion" in line_item

                latest_successful_order_id = json_dict_optional_str(line_item, "latestSuccessfulOrderId", err)

                if is_prepaid_plan and is_auto_renewing_plan:
                    err.msg_list.append(f'purchases.subscriptions.get line item has both auto_renewing_plan and prepaid_plan keys! This should never happen!')

                if is_deferred_replacement + is_deferred_removal + is_signup_promo > 1:
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

                    auto_renew_enabled = json_dict_optional_bool(auto_renewing_plan_obj, "autoRenewEnabled", False, err)

                    recurring_price = json_dict_require_google_money(auto_renewing_plan_obj, "recurringPrice", err)

                    has_installment_details = "installmentDetails" in auto_renewing_plan_obj
                    has_price_step_up_consent_details = "priceStepUpConsentDetails" in auto_renewing_plan_obj

                    price_change_details = None
                    price_change_details_obj = json_dict_optional_obj(auto_renewing_plan_obj, "priceChangeDetails", err)
                    if price_change_details_obj is not None:
                        new_price = json_dict_require_google_money(price_change_details_obj, "newPrice", err)

                        price_change_mode = json_dict_require_str_coerce_to_enum(price_change_details_obj, "priceChangeMode", SubscriptionV2SubscriptionItemPriceChangeDetailsModeType, err)
                        price_change_state = json_dict_require_str_coerce_to_enum(price_change_details_obj, "priceChangeState", SubscriptionV2SubscriptionItemPriceChangeDetailsStateType, err)
                        expected_new_price_charge_time = json_dict_require_google_timestamp(price_change_details_obj, "expectedNewPriceChargeTime", err)

                        if price_change_mode == SubscriptionV2SubscriptionItemPriceChangeDetailsModeType.PRICE_CHANGE_MODE_UNSPECIFIED:
                            err.msg_list.append(f'Invalid price change mode for line item price details: {price_change_mode}')

                        if price_change_state == SubscriptionV2SubscriptionItemPriceChangeDetailsStateType.PRICE_CHANGE_STATE_UNSPECIFIED:
                            err.msg_list.append(f'Invalid price change state for line item price details: {price_change_state}')

                        if not err.has():
                            price_change_details = SubscriptionV2SubscriptionItemPriceChangeDetails(
                                new_price=new_price,
                                price_change_mode=price_change_mode,
                                price_change_state=price_change_state,
                                expected_new_price_charge_time=expected_new_price_charge_time,
                            )

                    installment_details = None
                    installment_details_obj = json_dict_optional_obj(auto_renewing_plan_obj, "installmentDetails", err)
                    if installment_details_obj is not None:

                        initial_committed_payments_count = json_dict_require_int(installment_details_obj, "initialCommittedPaymentsCount", err)
                        subsequent_committed_payments_count = json_dict_require_int(installment_details_obj, "subsequentCommittedPaymentsCount", err)
                        remaining_committed_payments_count = json_dict_require_int(installment_details_obj, "remainingCommittedPaymentsCount", err)

                        pending_cancellation = None
                        pending_cancellation_obj = json_dict_optional_obj(installment_details_obj, "pendingCancellation", err)
                        if pending_cancellation_obj is not None:
                            pending_cancellation_state = json_dict_require_str_coerce_to_enum(pending_cancellation_obj, "state", SubscriptionV2SubscriptionPriceConsentStateType, err)

                            consent_deadline_time = json_dict_require_google_timestamp(installment_details_obj, "consentDeadlineTime", err)
                            new_price = json_dict_require_google_money(installment_details_obj, "newPrice", err)

                            if not err.has():
                                pending_cancellation = SubscriptionV2SubscriptionItemInstallmentPlanPendingCancellation(
                                    state=pending_cancellation_state,
                                    consent_deadline_time=consent_deadline_time,
                                    new_price=new_price,
                                )

                        if not err.has():
                            installment_details = SubscriptionV2SubscriptionItemInstallmentPlan(
                                initial_committed_payments_count=initial_committed_payments_count,
                                subsequent_committed_payments_count=subsequent_committed_payments_count,
                                remaining_committed_payments_count=remaining_committed_payments_count,
                                pending_cancellation=pending_cancellation,
                            )

                    price_step_up_consent_details = None
                    if has_price_step_up_consent_details:
                        price_step_up_consent_details = json_dict_require_str_coerce_to_enum(auto_renewing_plan_obj, "priceStepUpConsentDetails", SubscriptionV2SubscriptionPriceConsentStateType, err)

                    if not err.has():
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

                if not err.has():
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
            subscription_state = json_dict_require_str_coerce_to_enum(response, "subscriptionState", SubscriptionsV2SubscriptionStateType, err)
            linked_purchase_token = json_dict_optional_str(response, "linkedPurchaseToken", err)

            paused_state_context = None
            paused_state_context_obj = json_dict_optional_obj(response, "pausedStateContext", err)
            if paused_state_context_obj is not None:
                auto_resume_time = json_dict_require_google_timestamp(paused_state_context_obj, "autoResumeTime", err)

                if not err.has():
                    paused_state_context = SubscriptionsV2SubscriptionPausedStateContext(auto_resume_time=auto_resume_time)

            canceled_state_context = None
            canceled_state_context_obj = json_dict_optional_obj(response, "canceledStateContext", err)
            if canceled_state_context_obj is not None:
                user_initiated_cancellation = None
                user_initiated_cancellation_obj = json_dict_optional_obj(canceled_state_context_obj, "userInitiatedCancellation", err)
                is_user_initiated_cancellation = user_initiated_cancellation_obj is not None
                if is_user_initiated_cancellation:
                    cancel_survey_result_obj = json_dict_require_obj(user_initiated_cancellation_obj, "cancelSurveyResult", err)

                    reason = json_dict_require_str_coerce_to_enum(cancel_survey_result_obj, "reason", SubscriptionsV2SubscriptionCanceledStateContextUserSurveyResponseReason, err)
                    reason_user_input = json_dict_require_str(cancel_survey_result_obj, "reasonUserInput", err) if "reasonUserInput" in cancel_survey_result_obj else None

                    cancel_survey_result = SubscriptionsV2SubscriptionCanceledStateContextUserSurveyResponse(
                        reason=reason,
                        reason_user_input=reason_user_input
                    ) if not err.has() else None

                    cancel_time = json_dict_require_google_timestamp(user_initiated_cancellation_obj, "cancelTime", err)

                    if not err.has():
                        user_initiated_cancellation = SubscriptionsV2SubscriptionCanceledStateContextUser(
                            cancel_survey_result=cancel_survey_result,
                            cancel_time=cancel_time,
                        )

                is_system_initiated_cancellation = json_dict_optional_google_empty_object_bool(canceled_state_context_obj, "systemInitiatedCancellation", err)
                is_developer_initiated_cancellation = json_dict_optional_google_empty_object_bool(canceled_state_context_obj, "developerInitiatedCancellation", err)
                is_replacement_cancellation = json_dict_optional_google_empty_object_bool(response, "replacementCancellation", err)

                existing_keys = is_user_initiated_cancellation + is_system_initiated_cancellation + is_developer_initiated_cancellation + is_replacement_cancellation
                if existing_keys == 0:
                    err.msg_list.append(f'No cancellation state for plan')
                elif existing_keys > 1:
                    err.msg_list.append(f'Multiple cancellation state for plan. This is not possible!')

                if not err.has():
                    canceled_state_context = SubscriptionsV2SubscriptionCanceledStateContext(
                        user_initiated_cancellation=user_initiated_cancellation,
                        system_initiated_cancellation=is_system_initiated_cancellation,
                        developer_initiated_cancellation=is_developer_initiated_cancellation,
                        replacement_cancellation=is_replacement_cancellation
                    )


            is_test_purchase = json_dict_optional_google_empty_object_bool(response, "testPurchase", err)

            acknowledgement_state = json_dict_require_str_coerce_to_enum(response, "acknowledgementState", SubscriptionsV2SubscriptionAcknowledgementStateType, err)

            if not err.has() and acknowledgement_state is not None:
                result = SubscriptionV2Data(
                    kind=kind,
                    line_items=line_items,
                    start_time=start_time,
                    subscription_state=subscription_state,
                    linked_purchase_token=linked_purchase_token,
                    paused_state_context=paused_state_context,
                    canceled_state_context=canceled_state_context,
                    test_purchase=is_test_purchase,
                    acknowledgement_state=acknowledgement_state,
                )
        else:
            err.msg_list.append('Failed to get subscription details, result not a dict')

    except Exception as e:
        err.msg_list.append(f'Failed to get subscription details: {e}')

    assert result is None if err.has() else isinstance(result, SubscriptionV2Data)
    return result


def handle_not_implemented(name: str, err: base.ErrorSink):
    err.msg_list.append(f"'{name}' is not implemented!")


def handle_notification(body:dict, err: base.ErrorSink):
        body_version = json_dict_require_str(body, "version", err)
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
            err.msg_list.append(f'No subscription notification for {package_name}')
        elif unique_notif_keys > 1:
            err.msg_list.append(f'Multiple subscription notification for {package_name} {safe_dump_dict_keys_or_data(body)}')

        if err.has():
            return

        if is_subscription_notification:
            version = json_dict_require_str(subscription, "version",  err)
            subscription_notification_type = json_dict_require_int_coerce_to_enum(subscription, "notificationType", SubscriptionNotificationType, err)
            purchase_token = json_dict_require_str(subscription, "purchaseToken", err)

            if err.has():
                return

            assert subscription_notification_type is not None

            match subscription_notification_type:
                case SubscriptionNotificationType.SUBSCRIPTION_RECOVERED:
                    handle_not_implemented("SUBSCRIPTION_RECOVERED", err)
                case SubscriptionNotificationType.SUBSCRIPTION_RENEWED:
                    handle_not_implemented("SUBSCRIPTION_RENEWED", err)
                case SubscriptionNotificationType.SUBSCRIPTION_CANCELED:
                    handle_not_implemented("SUBSCRIPTION_CANCELED", err)
                case SubscriptionNotificationType.SUBSCRIPTION_PURCHASED:
                    details = get_subscription_v2(package_name, purchase_token, err)

                    if err.has():
                        err.msg_list.append(f'Parsing purchase token {purchase_token} failed')
                        return

                    assert details is not None

                    acknowledgement_state = details.acknowledgement_state
                    if acknowledgement_state == SubscriptionsV2SubscriptionAcknowledgementStateType.ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED:
                        err.msg_list.append(f'Message is already acknowledged')

                    # TODO: if linked_purchase_token exits we need to revoke the old subscription proof

                    if details.test_purchase is not None:
                        print(details.test_purchase)

                    if err.has():
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
                    err.msg_list.append(f'subscription notificationType SUBSCRIPTION_DEFERRED ({subscription_notification_type}) is unsupported!')
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
                    err.msg_list.append(f'subscription notificationType is invalid: {subscription_notification_type}')

        elif is_voided_notification:
            purchase_token = json_dict_require_str(voided_purchase, "purchaseToken", err)
            order_id = json_dict_require_str(voided_purchase, "orderId", err)
            product_type = json_dict_require_int_coerce_to_enum(voided_purchase, "productType", ProductType, err)
            refund_type = json_dict_require_int_coerce_to_enum(voided_purchase, "refundType", RefundType, err)

            if err.has():
                return

            assert refund_type is not None and product_type is not None

            match product_type:
                case ProductType.PRODUCT_TYPE_SUBSCRIPTION:
                    match refund_type:
                        case RefundType.REFUND_TYPE_FULL_REFUND:
                            handle_not_implemented("handle_subscription_refund", err)
                        case RefundType.REFUND_TYPE_QUANTITY_BASED_PARTIAL_REFUND:
                            # TODO: we need to check if this is actually unsupported, as far as a i can tell it doesnt relate to subscriptions
                            err.msg_list.append(f'voided purchase refundType REFUND_TYPE_QUANTITY_BASED_PARTIAL_REFUND ({refund_type}) is unsupported!')
                        case _:
                            err.msg_list.append(f'voided purchase refundType is not valid: {refund_type}')
                case ProductType.PRODUCT_TYPE_ONE_TIME:
                    err.msg_list.append(f'voided purchase productType PRODUCT_TYPE_ONE_TIME ({product_type}) is unsupported!')
                case _:
                    err.msg_list.append(f'voided purchase productType is not valid: {product_type}')

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

    data = None
    try:
        # calling data on message calls a method, this shouldn't be able to fail, but we should still handle the case
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
        try:
            handle_notification(body, err)
        except Exception as e:
            err.msg_list.append(f"Failed to handle notification: {e}")
    else:
        err.msg_list.append("Message data is not a valid JSON object")

    if err.has():
        err_msg = '\n'.join(err.msg_list)
        logging.error(f'ERROR: {err_msg}\nPayload was: {safe_dump_dict_keys_or_data(body)}')
    else:
        print('ACK')
        message.ack()

def entry_point():
    # TODO: these env parsers are needed here if used as an entry point, they need to be removed if/when this changes
    env.GOOGLE_APPLICATION_CREDENTIALS = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')

    if not env.GOOGLE_APPLICATION_CREDENTIALS:
        raise ValueError("GOOGLE_APPLICATION_CREDENTIALS environment variable not set")

    if not os.path.exists(env.GOOGLE_APPLICATION_CREDENTIALS):
        raise FileNotFoundError(f"Service account file not found: {env.GOOGLE_APPLICATION_CREDENTIALS}")

    env.SESH_PRO_BACKEND_UNSAFE_LOGGING = os_get_boolean_env('SESH_PRO_BACKEND_UNSAFE_LOGGING', False)

    with pubsub_v1.SubscriberClient() as sub_client:
        sub_path = sub_client.subscription_path(project='loki-5a81e', subscription='session-pro-sub')
        future = sub_client.subscribe(subscription=sub_path, callback=callback)
        try:
            future.result()
        except KeyboardInterrupt:
            future.cancel()  # Trigger the shutdown.
            future.result()  # Block until the shutdown is complete.

entry_point()