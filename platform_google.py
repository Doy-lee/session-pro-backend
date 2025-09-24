import json
import logging
import os
import sqlite3
import sys
import typing

from google.cloud import pubsub_v1
import google.cloud.pubsub_v1.subscriber.message

import backend
import base
from backend import PaymentProviderTransaction, AddRevocationItem
from base import json_dict_require_str, json_dict_require_int, json_dict_require_str_coerce_to_int, \
    safe_dump_dict_keys_or_data, json_dict_require_obj, json_dict_require_array, json_dict_require_bool, \
    json_dict_require_str_coerce_to_enum, json_dict_optional_bool, safe_dump_arbitrary_value_or_type, \
    json_dict_optional_str, json_dict_optional_obj, json_dict_require_int_coerce_to_enum, \
    parse_enum_to_str, obfuscate, get_now_ms

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
    json_dict_optional_google_empty_object_bool, SubscriptionProductDetails

SCOPES = ['https://www.googleapis.com/auth/androidpublisher']

def create_service():
    """Create and return the Android Publisher service object using environment credentials."""
    # Get the service account file path from environment variable
    credentials = service_account.Credentials.from_service_account_file(
        env.GOOGLE_APPLICATION_CREDENTIALS, scopes=SCOPES)

    service = build('androidpublisher', 'v3', credentials=credentials)
    return service


def get_subscription_info(package_name: str, product_id: str, err: base.ErrorSink):
    service = create_service()
    result = None
    try:
        response = service.monetization().subscriptions().get(
            packageName=package_name,
            productId=product_id
        ).execute()

        result = response
    except Exception as e:
        err.msg_list.append(f'Failed to get subscription details: {e}')

    # assert result is None if err.has() else isinstance(result, SubscriptionV2Data)
    return result


def get_subscription_details_for_product_id(package_name: str, product_id: str, err: base.ErrorSink) -> dict[str, SubscriptionProductDetails] | None:
    result = None

    subscriptions = get_subscription_info(package_name, product_id, err)
    if subscriptions is None:
        return result

    base_plans = json_dict_require_array(subscriptions, "basePlans", err)

    for plan in base_plans:
        base_plan_id = json_dict_require_str(plan, "basePlanId", err)
        auto_renewing_base_plan_type = json_dict_optional_obj(plan, "autoRenewingBasePlanType", err)
        grace_period_duration = json_dict_require_str(auto_renewing_base_plan_type, "gracePeriodDuration", err)
        billing_period_duration = json_dict_require_str(auto_renewing_base_plan_type, "billingPeriodDuration", err)

        if grace_period_duration[0] != "P":
            err.msg_list.append(f'Grace period duration must be ISO 8601 format but does not start with "P" ({grace_period_duration[0]})')
        if grace_period_duration[-1] != "D":
            err.msg_list.append(f'Grace period duration must be ISO 8601 format but does not end with "D" ({grace_period_duration[-0]})')

        billing_period_unit = billing_period_duration[-1]

        if billing_period_duration[0] != "P":
            err.msg_list.append(f'Billing period duration must be ISO 8601 format but does not start with "P" ({billing_period_duration[0]})')
        if billing_period_unit not in ["D", "M", "Y"]:
            err.msg_list.append(f'Billing period duration must be ISO 8601 format but does not end with "D", "M" or "Y" ({billing_period_unit})')

        if err.has():
            continue

        grace_period_days_str = grace_period_duration[1:-1]
        grace_period_ms = None
        try:
            grace_period_days = int(grace_period_days_str)
            if grace_period_days < 0:
                err.msg_list.append(f'Grace period cannot be less than 0: {grace_period_days}')
            else:
                grace_period_ms = grace_period_days * base.MILLISECONDS_IN_DAY
        except Exception as e:
            err.msg_list.append(f'Failed to parse grace period days "{grace_period_days_str}": {e}')

        billing_period_n_str = billing_period_duration[1:-1]
        billing_period_n_int = None
        try:
            billing_period_n_int = int(billing_period_n_str)
            if billing_period_n_int < 0:
                err.msg_list.append(f'Billing period cannot be less than 0: {billing_period_n_int}')
        except Exception as e:
            err.msg_list.append(f'Failed to parse billing period "{billing_period_n_str}": {e}')

        if err.has():
            continue

        billing_period_s = None
        match billing_period_unit:
            case "D":
                billing_period_s = billing_period_n_int * base.SECONDS_IN_DAY
            case "M":
                billing_period_s = billing_period_n_int * base.SECONDS_IN_MONTH
            case "Y":
                billing_period_s = billing_period_n_int * base.SECONDS_IN_YEAR
            case _:
                err.msg_list.append(f'Unsupported billing period unit: {billing_period_unit}')

        if err.has():
            continue

        if result is None:
            result = {}

        result[base_plan_id] = SubscriptionProductDetails(
            billing_period_s=billing_period_s,
            grace_period_ms=grace_period_ms,
        )

    return result


def get_subscription_details_for_plan(plan_id: str, err: base.ErrorSink):
    details = get_subscription_details_for_product_id(platform_config.google_package_name, platform_config.google_subscription_product_id, err)
    if details is None:
        err.msg_list.append(f'Failed to get details for {platform_config.google_package_name} and {platform_config.google_subscription_product_id}')

    plan_details = details[plan_id] if plan_id in details else None

    if plan_details is None:
        err.msg_list.append(f'Unable to find plan details for plan_id {plan_id}')

    return plan_details


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

def get_line_item(details: SubscriptionV2Data, err: base.ErrorSink):
    result = None
    if len(details.line_items) == 0:
        err.msg_list.append(f"No line items for subscription!")
    else:
        line_item = details.line_items[0]
        if line_item is None:
            err.msg_list.append(f"No line item for subscription!")
        else:
            result = line_item
    return result

def queue_user_entitlement_amend(purchase_token: str, details: SubscriptionV2Data, err: base.ErrorSink):
    line_item = get_line_item(details, err)

    if err.has():
        err.msg_list.append(f'Failed to add user entitlement for {purchase_token}')
        return

    details = get_subscription_details_for_plan(line_item.product_id, err)

    if err.has():
        err.msg_list.append(f'Failed to add user entitlement for {purchase_token}')
        return

    tx = PaymentProviderTransaction(
        provider=base.PaymentProvider.GooglePlayStore,
        google_order_id=line_item.offer_details.offer_id,
        google_payment_token=purchase_token,
    )

    sql_conn = sqlite3.connect(env.SESH_PRO_BACKEND_DB_PATH)

    backend.update_payment_unix_ts_ms(
        sql_conn=sql_conn,
        payment_tx=tx,
        grace_unix_ts_ms=details.grace_period_ms,
        expiry_unix_ts_ms=line_item.expiry_time.unix_milliseconds,
        err=err,
    )


def queue_user_entitlement_remove_grace_period(purchase_token: str, details: SubscriptionV2Data, err: base.ErrorSink):
    line_item = get_line_item(details, err)

    if err.has():
        err.msg_list.append(f'Failed to add user entitlement for {purchase_token}')
        return

    details = get_subscription_details_for_plan(line_item.product_id, err)

    if err.has():
        err.msg_list.append(f'Failed to add user entitlement for {purchase_token}')
        return

    tx = PaymentProviderTransaction(
        provider=base.PaymentProvider.GooglePlayStore,
        google_order_id=line_item.offer_details.offer_id,
        google_payment_token=purchase_token,
    )

    sql_conn = sqlite3.connect(env.SESH_PRO_BACKEND_DB_PATH)

    backend.update_payment_unix_ts_ms(
        sql_conn=sql_conn,
        payment_tx=tx,
        grace_unix_ts_ms=0,
        expiry_unix_ts_ms=line_item.expiry_time.unix_milliseconds,
        err=err,
    )


def queue_user_entitlement_grant(purchase_token: str, details: SubscriptionV2Data, err: base.ErrorSink):
    line_item = get_line_item(details, err)

    if err.has():
        err.msg_list.append(f'Failed to add user entitlement for {purchase_token}')
        return

    details = get_subscription_details_for_plan(line_item.product_id, err)

    if err.has():
        err.msg_list.append(f'Failed to add user entitlement for {purchase_token}')
        return


    tx = PaymentProviderTransaction(
        provider=base.PaymentProvider.GooglePlayStore,
        google_order_id=line_item.offer_details.offer_id,
        google_payment_token=purchase_token,
    )

    sql_conn = sqlite3.connect(env.SESH_PRO_BACKEND_DB_PATH)

    backend.add_unredeemed_payment(
        sql_conn=sql_conn,
        payment_tx=tx,
        subscription_duration_s=details.billing_period_s,
        grace_unix_ts_ms=details.grace_period_ms,
        expiry_unix_ts_ms=line_item.expiry_time.unix_milliseconds,
        err=err,
    )


def queue_user_entitlement_revoke(details: SubscriptionV2Data, err: base.ErrorSink):
    line_item = get_line_item(details, err)
    if err.has():
        err.msg_list.append(f'Failed to revoke entitlement')
        return

    sql_conn = sqlite3.connect(env.SESH_PRO_BACKEND_DB_PATH)

    revocation = AddRevocationItem(
        payment_provider=base.PaymentProvider.GooglePlayStore,
        tx_id=line_item.offer_details.offer_id,
    )

    if err.has():
        err.msg_list.append(f'Failed to revoke entitlement')
        return

    backend.add_revocation(
        sql_conn=sql_conn,
        revocation=revocation,
    )


def handle_notification(body: dict, err: base.ErrorSink):
        body_version = json_dict_require_str(body, "version", err)
        package_name = json_dict_require_str(body, "packageName", err)
        event_time_millis = json_dict_require_str_coerce_to_int(body, "eventTimeMillis", err)

        now_ms = get_now_ms()

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

            details = get_subscription_v2(package_name, purchase_token, err)

            if err.has():
                err.msg_list.append(f'Parsing purchase token {obfuscate(purchase_token)} failed')
                return

            assert details is not None

            acknowledgement_state = details.acknowledgement_state
            if acknowledgement_state == SubscriptionsV2SubscriptionAcknowledgementStateType.ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED:
                err.msg_list.append(f'Message is already acknowledged')

            if err.has():
                return

            match subscription_notification_type:
                case SubscriptionNotificationType.SUBSCRIPTION_RECOVERED | SubscriptionNotificationType.SUBSCRIPTION_RENEWED:
                    if details.subscription_state != SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_ACTIVE:
                        err.msg_list.append(f'Subscription state is {parse_enum_to_str(details.subscription_state)} in a {parse_enum_to_str(subscription_notification_type)}')

                    if not err.has():
                        queue_user_entitlement_grant(purchase_token, details, err)

                case SubscriptionNotificationType.SUBSCRIPTION_CANCELED:
                    if details.subscription_state != SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_CANCELED:
                        err.msg_list.append(f'Subscription state is {parse_enum_to_str(details.subscription_state)} in a {parse_enum_to_str(subscription_notification_type)}')

                    if not err.has():
                        queue_user_entitlement_remove_grace_period(purchase_token, details, err)

                case SubscriptionNotificationType.SUBSCRIPTION_PURCHASED:
                    """
                    These are the steps documented by Google:
                    When a user purchases a subscription, a SubscriptionNotification message with type SUBSCRIPTION_PURCHASED is sent to your RTDN client. Whether you receive this notification or you register a new purchase in-app through PurchasesUpdatedListener or manually fetching purchases in your app's onResume() method, you should process the new purchase in your secure backend. To do this, follow these steps:
                    1. Query the purchases.subscriptionsv2.get endpoint to get a subscription resource that contains the latest subscription state.
                    2. Make sure that the value of the subscriptionState field is SUBSCRIPTION_STATE_ACTIVE.
                    3. Verify the purchase.
                    4. Give the user access to the content. The user account associated with the purchase can be identified with the ExternalAccountIdentifiers object from the subscription resource if identifiers were set at purchase time using setObfuscatedAccountId and setObfuscatedProfileId.
                    """
                    if details.subscription_state == SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_PENDING:
                        # TODO: maybe we want to handle pending state differently
                        err.msg_list.append(f'Subscription state is {parse_enum_to_str(details.subscription_state)} in a {parse_enum_to_str(subscription_notification_type)}. This can be ignored.')
                    elif details.subscription_state != SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_ACTIVE:
                        err.msg_list.append(f'Subscription state is {parse_enum_to_str(details.subscription_state)} in a {parse_enum_to_str(subscription_notification_type)}')

                    if not err.has():
                        if details.linked_purchase_token is not None:
                            queue_user_entitlement_revoke(details, err)
                            if err.has():
                                err.msg_list.append(f'Failed to revoke linked purchase token {obfuscate(details.linked_purchase_token)} associated with new purchase token {obfuscate(purchase_token)}')

                        if not err.has():
                            queue_user_entitlement_grant(purchase_token, details, err)

                case SubscriptionNotificationType.SUBSCRIPTION_ON_HOLD:
                    # No entitlement change required
                    pass

                case SubscriptionNotificationType.SUBSCRIPTION_IN_GRACE_PERIOD:
                    # No entitlement change required
                    pass

                case SubscriptionNotificationType.SUBSCRIPTION_RESTARTED:
                    if details.subscription_state != SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_ACTIVE:
                        err.msg_list.append(f'Subscription state is {parse_enum_to_str(details.subscription_state)} in a {parse_enum_to_str(subscription_notification_type)}')

                    if not err.has():
                        queue_user_entitlement_amend(purchase_token, details, err)

                case SubscriptionNotificationType.SUBSCRIPTION_PRICE_CHANGE_CONFIRMED:
                    # No entitlement change required
                    pass

                case SubscriptionNotificationType.SUBSCRIPTION_DEFERRED:
                    err.msg_list.append(f'Subscription notificationType {parse_enum_to_str(subscription_notification_type)} is unsupported!')

                case SubscriptionNotificationType.SUBSCRIPTION_PAUSED:
                    err.msg_list.append(f'Subscription notificationType {parse_enum_to_str(subscription_notification_type)} is unsupported!')

                case SubscriptionNotificationType.SUBSCRIPTION_PAUSE_SCHEDULE_CHANGED:
                    err.msg_list.append(f'Subscription notificationType {parse_enum_to_str(subscription_notification_type)} is unsupported!')

                case SubscriptionNotificationType.SUBSCRIPTION_REVOKED:
                    if details.subscription_state != SubscriptionsV2SubscriptionStateType.SUBSCRIPTION_STATE_EXPIRED:
                        err.msg_list.append(f'Subscription state is {parse_enum_to_str(details.subscription_state)} in a {parse_enum_to_str(subscription_notification_type)}')

                    if not err.has():
                        queue_user_entitlement_revoke(details, err)

                case SubscriptionNotificationType.SUBSCRIPTION_EXPIRED:
                    # No entitlement change required
                    pass

                case SubscriptionNotificationType.SUBSCRIPTION_PRICE_CHANGE_UPDATED:
                    # No entitlement change required
                    pass

                case SubscriptionNotificationType.SUBSCRIPTION_PENDING_PURCHASE_CANCELED:
                    line_item = get_line_item(details, err)
                    # TODO: Collect cancel reason
                    if not err.has() and line_item.expiry_time.unix_milliseconds < now_ms:
                        queue_user_entitlement_revoke(details, err)

                case SubscriptionNotificationType.SUBSCRIPTION_PRICE_STEP_UP_CONSENT_UPDATED:
                    # No entitlement change required
                    pass

                case _:
                    err.msg_list.append(f'subscription notificationType is invalid: {parse_enum_to_str(subscription_notification_type)}')

            if err.has():
                err.msg_list.append(f'Failed to handle {parse_enum_to_str(details.subscription_state)} for token {obfuscate(purchase_token)}')
                return

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
                            handle_not_implemented(parse_enum_to_str(refund_type), err)
                        case RefundType.REFUND_TYPE_QUANTITY_BASED_PARTIAL_REFUND:
                            # TODO: we need to check if this is actually unsupported, as far as a i can tell it doesnt relate to subscriptions
                            err.msg_list.append(f'voided purchase refundType {parse_enum_to_str(refund_type)} is unsupported!')
                        case _:
                            err.msg_list.append(f'voided purchase refundType is not valid: {parse_enum_to_str(refund_type)}')
                case ProductType.PRODUCT_TYPE_ONE_TIME:
                    err.msg_list.append(f'voided purchase productType {parse_enum_to_str(product_type)} is unsupported!')
                case _:
                    err.msg_list.append(f'voided purchase productType is not valid: {parse_enum_to_str(product_type)}')

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

    env.SESH_PRO_BACKEND_DB_PATH  = os.getenv('SESH_PRO_BACKEND_DB_PATH', './backend.db')

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