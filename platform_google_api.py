import dataclasses
import typing
import base
from base import JSONObject, handle_not_implemented, json_dict_require_str, json_dict_require_int, json_dict_require_str_coerce_to_int, \
    safe_dump_dict_keys_or_data, json_dict_require_obj, json_dict_require_array, json_dict_require_bool, \
    json_dict_require_str_coerce_to_enum, json_dict_optional_bool, safe_dump_arbitrary_value_or_type, \
    json_dict_optional_str, json_dict_optional_obj, json_dict_require_int_coerce_to_enum, \
    dump_enum_details, obfuscate, validate_string_list

import env
from googleapiclient.discovery import build
from google.oauth2 import service_account

import platform_config
from platform_google_types import Monetizationv3SubscriptionData, SubscriptionNotificationType, \
    SubscriptionsV2SubscriptionAcknowledgementStateType, RefundType, ProductType, SubscriptionV2Data, GoogleTimestamp, \
    SubscriptionV2DataOfferDetails, GoogleMoney, SubscriptionV2SubscriptionItemPriceChangeDetails, \
    SubscriptionV2SubscriptionItemPriceChangeDetailsModeType, SubscriptionV2SubscriptionItemPriceChangeDetailsStateType, \
    SubscriptionV2DataAutoRenewingPlan, SubscriptionV2SubscriptionPriceConsentStateType, json_dict_require_google_duration, json_dict_require_google_money, \
    json_dict_require_google_timestamp, SubscriptionV2SubscriptionItemInstallmentPlanPendingCancellation, \
    SubscriptionV2SubscriptionItemInstallmentPlan, SubscriptionV2DataLineItem, SubscriptionsV2SubscriptionStateType, \
    SubscriptionsV2SubscriptionPausedStateContext, \
    SubscriptionsV2SubscriptionCanceledStateContextUserSurveyResponseReason, \
    SubscriptionsV2SubscriptionCanceledStateContextUser, \
    SubscriptionsV2SubscriptionCanceledStateContextUserSurveyResponse, SubscriptionsV2SubscriptionCanceledStateContext, \
    json_dict_optional_google_empty_object_bool, SubscriptionProductDetails

SCOPES = ['https://www.googleapis.com/auth/androidpublisher']

def create_service():
    """Create and return the Android Publisher service object using environment credentials."""
    credentials = service_account.Credentials.from_service_account_file(
        env.GOOGLE_APPLICATION_CREDENTIALS, scopes=SCOPES)

    service = build('androidpublisher', 'v3', credentials=credentials)
    return service

def parse_google_api_fetch_subscription_v2_response(response: typing.Any, err: base.ErrorSink) -> SubscriptionV2Data | None:
    result = None
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

            for tag in offer_details_offer_tags:
                if not isinstance(tag, str):
                    err.msg_list.append(f"Tag in offerTags is not a string: {safe_dump_arbitrary_value_or_type(tag)}")
            
            assert validate_string_list(offer_details_offer_tags)

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
                        assert isinstance(price_change_mode, SubscriptionV2SubscriptionItemPriceChangeDetailsModeType)
                        assert isinstance(price_change_state, SubscriptionV2SubscriptionItemPriceChangeDetailsStateType)

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
                            assert isinstance(pending_cancellation_state, SubscriptionV2SubscriptionPriceConsentStateType)
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

                assert offer_details is not None

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
                cancel_survey_result_obj = json_dict_optional_obj(user_initiated_cancellation_obj, "cancelSurveyResult", err)

                cancel_survey_result = None
                if cancel_survey_result_obj is not None:
                    reason = json_dict_require_str_coerce_to_enum(cancel_survey_result_obj, "reason", SubscriptionsV2SubscriptionCanceledStateContextUserSurveyResponseReason, err)
                    reason_user_input = json_dict_require_str(cancel_survey_result_obj, "reasonUserInput", err) if "reasonUserInput" in cancel_survey_result_obj else None

                    if not err.has():
                        assert reason is not None
                        cancel_survey_result = SubscriptionsV2SubscriptionCanceledStateContextUserSurveyResponse(
                            reason=reason,
                            reason_user_input=reason_user_input
                        )

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


    assert result is None if err.has() else isinstance(result, SubscriptionV2Data)
    return result


def google_api_fetch_subscription_v2(package_name: str, purchase_token: str, err: base.ErrorSink) -> SubscriptionV2Data | None:
    """
    Call the purchases.subscriptionsv2.get endpoint. https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.subscriptionsv2/get
    """
    service = create_service()
    response = service.purchases().subscriptionsv2().get(
        packageName=package_name,
        token=purchase_token
    ).execute()
    print(response)
    print(",")

    return parse_google_api_fetch_subscription_v2_response(response, err)


def google_api_fetch_monetizationv3_subscriptions_for_product_id(package_name: str, product_id: str, err: base.ErrorSink) -> Monetizationv3SubscriptionData | None:
    """
    Call the Google monetizationv3.subscriptions.get endpoint: https://developers.google.com/android-publisher/api-ref/rest/v3/monetization.subscriptions/get 
    """
    service = create_service()
    result = None
    response = service.monetization().subscriptions().get(
        packageName=package_name,
        productId=product_id
    ).execute()

    if isinstance(response, dict):
        base_plans = json_dict_require_array(response, "basePlans", err)
        
        if not err.has():
            result = Monetizationv3SubscriptionData(
                base_plans=base_plans
            )

    else:
        err.msg_list.append(f'Subscription info response is not a valid dict: {safe_dump_arbitrary_value_or_type(response)}')

    assert result is None if err.has() else isinstance(result, Monetizationv3SubscriptionData)
    return result


def google_api_fetch_subscription_details_for_base_plan_id(base_plan_id: str, err: base.ErrorSink) -> SubscriptionProductDetails | None:
    """
    Internally calls the Google monetization v3 api
    """
    result = None

    subscriptions = google_api_fetch_monetizationv3_subscriptions_for_product_id(
        package_name=platform_config.google_package_name,
        product_id=platform_config.google_subscription_product_id,
        err=err)
    
    if err.has():
        err.msg_list.append(f'Failed to get subscription details for {platform_config.google_package_name} and {platform_config.google_subscription_product_id}')
        return result

    assert(subscriptions is not None)

    result = None
    for plan in subscriptions.base_plans:
        assert(plan is not None)

        if not isinstance(plan, dict):
            err.msg_list.append(f'Plan is not a dict: {type(plan)}')
            continue

        result_base_plan_id = json_dict_require_str(plan, "basePlanId", err)

        if result_base_plan_id != base_plan_id:
            continue

        auto_renewing_base_plan_type = json_dict_require_obj(plan, "autoRenewingBasePlanType", err)
        grace_period = json_dict_require_google_duration(auto_renewing_base_plan_type, "gracePeriodDuration", err)
        billing_period = json_dict_require_google_duration(auto_renewing_base_plan_type, "billingPeriodDuration", err)

        if err.has():
            continue

        result = SubscriptionProductDetails(
            billing_period=billing_period,
            grace_period=grace_period,
        )
        break;

    if result is None:
        err.msg_list.append(f'Unable to find plan details for plan_id "{base_plan_id}", plan_details was {subscriptions.base_plans}')

    assert result is None if err.has() else isinstance(result, SubscriptionProductDetails)

    return result
 
def get_line_item(details: SubscriptionV2Data) -> SubscriptionV2DataLineItem:
    assert len(details.line_items) > 0
    return details.line_items[0]


def get_valid_order_id(details: SubscriptionV2Data, err: base.ErrorSink) -> str:
    result = ""
    line_item = get_line_item(details)
    if line_item.latest_successful_order_id is None:
        err.msg_list.append(f"Order id is None is subscription but was required!")
    else:
        result = line_item.latest_successful_order_id

    return result

@dataclasses.dataclass
class SubscriptionPlanTxFields:
    # ID of the Google subscription's base plan. Not the product_id.
    base_plan_id: str
    # Unique ID of the successful order
    order_id: str
    # Time at which the subscription expires
    expiry_time: GoogleTimestamp
    # Timestamp in ms when the event occured
    event_ts_ms: int

def get_subscription_plan_tx_fields(details: SubscriptionV2Data, event_ts_ms: int, err: base.ErrorSink) -> SubscriptionPlanTxFields:
    line_item = get_line_item(details)
    order_id = get_valid_order_id(details, err)
    return SubscriptionPlanTxFields(
        base_plan_id=line_item.offer_details.base_plan_id,
        order_id=order_id,
        expiry_time=line_item.expiry_time,
        event_ts_ms=event_ts_ms,
    )

