import dataclasses
import typing
from enum import IntEnum, StrEnum
from typing import Optional

from google.protobuf.internal.well_known_types import Timestamp

import base

class GoogleTimestamp(Timestamp):
    rfc3339: str
    unix_milliseconds: int
    unix_seconds: int

    def __init__(self, rfc3339_timestamp: str, err: base.ErrorSink):
        self.rfc3339 = rfc3339_timestamp
        try:
            self.FromJsonString(rfc3339_timestamp)
            self.unix_milliseconds = self.ToMilliseconds()
            self.unix_seconds = self.ToSeconds()
        except Exception as e:
            err.msg_list.append(f'Failed to parse timestamp "{rfc3339_timestamp}": {e}')


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

class SubscriptionsV2SubscriptionStateType(StrEnum):
    """Subscriptions V2 subscription state types"""
    # Unspecified subscription state.
    SUBSCRIPTION_STATE_UNSPECIFIED = "SUBSCRIPTION_STATE_UNSPECIFIED"
    # Subscription was created but awaiting payment during signup. In this state, all items are awaiting payment.
    SUBSCRIPTION_STATE_PENDING = "SUBSCRIPTION_STATE_PENDING"
    # Subscription is active. - (1) If the subscription is an auto renewing plan, at least one item is autoRenewEnabled and not expired. - (2) If the subscription is a prepaid plan, at least one item is not expired.
    SUBSCRIPTION_STATE_ACTIVE = "SUBSCRIPTION_STATE_ACTIVE"
    # Subscription is paused. The state is only available when the subscription is an auto renewing plan. In this state, all items are in paused state.
    SUBSCRIPTION_STATE_PAUSED = "SUBSCRIPTION_STATE_PAUSED"
    # Subscription is in grace period. The state is only available when the subscription is an auto renewing plan. In this state, all items are in grace period.
    SUBSCRIPTION_STATE_IN_GRACE_PERIOD = "SUBSCRIPTION_STATE_IN_GRACE_PERIOD"
    # Subscription is on hold (suspended). The state is only available when the subscription is an auto renewing plan. In this state, all items are on hold.
    SUBSCRIPTION_STATE_ON_HOLD = "SUBSCRIPTION_STATE_ON_HOLD"
    # Subscription is canceled but not expired yet. The state is only available when the subscription is an auto renewing plan. All items have autoRenewEnabled set to false.
    SUBSCRIPTION_STATE_CANCELED = "SUBSCRIPTION_STATE_CANCELED"
    # Subscription is expired. All items have expiryTime in the past.
    SUBSCRIPTION_STATE_EXPIRED = "SUBSCRIPTION_STATE_EXPIRED"
    # Pending transaction for subscription is canceled. If this pending purchase was for an existing subscription, use linkedPurchaseToken to get the current state of that subscription.
    SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED = "SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED"

class SubscriptionsV2SubscriptionAcknowledgementStateType(StrEnum):
    """Subscriptions V2 subscription Acknowledgement state types"""
    # Unspecified acknowledgement state.
    ACKNOWLEDGEMENT_STATE_UNSPECIFIED = "ACKNOWLEDGEMENT_STATE_UNSPECIFIED"
    # The subscription is not acknowledged yet.
    ACKNOWLEDGEMENT_STATE_PENDING = "ACKNOWLEDGEMENT_STATE_PENDING"
    # The subscription is acknowledged.
    ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED = "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED"

class SubscriptionsV2SubscriptionCanceledStateContextUserSurveyResponseReason(StrEnum):
    """The reason the user selected in the cancel survey."""
    # Unspecified cancel survey reason.
    CANCEL_SURVEY_REASON_UNSPECIFIED = "CANCEL_SURVEY_REASON_UNSPECIFIED"
    # Not enough usage of the subscription.
    CANCEL_SURVEY_REASON_NOT_ENOUGH_USAGE = "CANCEL_SURVEY_REASON_NOT_ENOUGH"
    # Technical issues while using the app.
    CANCEL_SURVEY_REASON_TECHNICAL_ISSUES = "CANCEL_SURVEY_REASON_TECHNICAL_ISSUES"
    # Cost related issues.
    CANCEL_SURVEY_REASON_COST_RELATED = "CANCEL_SURVEY_REASON_COST_RELATED"
    # The user found a better app.
    CANCEL_SURVEY_REASON_FOUND_BETTER_APP = "CANCEL_SURVEY_REASON_FOUND_BETTER_APP"
    # Other reasons.
    CANCEL_SURVEY_REASON_OTHERS = "CANCEL_SURVEY_REASON_OTHERS"

@dataclasses.dataclass
class SubscriptionsV2SubscriptionPausedStateContext:
    """Information specific to a subscription in paused state."""
    # Time at which the subscription will be automatically resumed.
    # Uses RFC 3339, where generated output will always be Z-normalized and use 0, 3, 6 or 9 fractional digits. Offsets other than "Z" are also accepted. Examples: "2014-10-02T15:01:23Z", "2014-10-02T15:01:23.045123456Z" or "2014-10-02T15:01:23+05:30".
    auto_resume_time: GoogleTimestamp


@dataclasses.dataclass
class SubscriptionsV2SubscriptionCanceledStateContextUserSurveyResponse:
    """Result of the cancel survey when the subscription was canceled by the user."""
    # The reason the user selected in the cancel survey.
    reason: SubscriptionsV2SubscriptionCanceledStateContextUserSurveyResponseReason
    # Only set for CANCEL_SURVEY_REASON_OTHERS. This is the user's freeform response to the survey.
    reason_user_input: Optional[str]

# TODO: we need to collect cancel reasons
@dataclasses.dataclass
class SubscriptionsV2SubscriptionCanceledStateContextUser:
    # Information provided by the user when they complete the subscription cancellation flow (cancellation reason survey).
    cancel_survey_result: SubscriptionsV2SubscriptionCanceledStateContextUserSurveyResponse
    # The time at which the subscription was canceled by the user. The user might still have access to the subscription after this time. Use lineItems.expiry_time to determine if a user still has access.
    # Uses RFC 3339, where generated output will always be Z-normalized and use 0, 3, 6 or 9 fractional digits. Offsets other than "Z" are also accepted. Examples: "2014-10-02T15:01:23Z", "2014-10-02T15:01:23.045123456Z" or "2014-10-02T15:01:23+05:30".
    cancel_time: GoogleTimestamp

@dataclasses.dataclass
class SubscriptionsV2SubscriptionCanceledStateContext:
    """
    Information specific to a subscription in the SUBSCRIPTION_STATE_CANCELED or SUBSCRIPTION_STATE_EXPIRED state.
    Only one of the fields can exist.
    """
    # Subscription was canceled by user.
    user_initiated_cancellation: Optional[SubscriptionsV2SubscriptionCanceledStateContextUser]
    # Subscription was canceled by the system, for example because of a billing problem. (empty object bool)
    system_initiated_cancellation: bool
    # Subscription was canceled by the developer. (empty object bool)
    developer_initiated_cancellation: bool
    # Subscription was replaced by a new subscription. (empty object bool)
    replacement_cancellation: bool


@dataclasses.dataclass
class GoogleMoney:
    # The three-letter currency code defined in ISO 4217
    currency_code: str
    # The whole units of the amount. For example if currencyCode is "USD", then 1 unit is one US dollar.
    units: str
    # Number of nano (10^-9) units of the amount. The value must be between -999,999,999 and +999,999,999 inclusive. If units is positive, nanos must be positive or zero. If units is zero, nanos can be positive, zero, or negative. If units is negative, nanos must be negative or zero. For example $-1.75 is represented as units=-1 and nanos=-750,000,000.
    nanos: int

class SubscriptionV2SubscriptionItemPriceChangeDetailsModeType(StrEnum):
    # Price change mode unspecified. This value should never be set.
    PRICE_CHANGE_MODE_UNSPECIFIED = "PRICE_CHANGE_MODE_UNSPECIFIED"
    # If the subscription price is decreasing.
    PRICE_DECREASE = "PRICE_DECREASE"
    # If the subscription price is increasing and the user needs to accept it.
    PRICE_INCREASE = "PRICE_INCREASE"
    # If the subscription price is increasing with opt out mode.
    OPT_OUT_PRICE_INCREASE = "OPT_OUT_PRICE_INCREASE"

class SubscriptionV2SubscriptionItemPriceChangeDetailsStateType(StrEnum):
    # Price change state unspecified. This value should not be used.
    PRICE_CHANGE_STATE_UNSPECIFIED = "PRICE_CHANGE_STATE_UNSPECIFIED"
    # Waiting for the user to agree for the price change.
    OUTSTANDING = "OUTSTANDING"
    # The price change is confirmed to happen for the user.
    CONFIRMED = "CONFIRMED"
    # The price change is applied, i.e. the user has started being charged the new price.
    APPLIED = "APPLIED"
    # The price change was canceled.
    CANCELED = "CANCELED"

@dataclasses.dataclass
class SubscriptionV2SubscriptionItemPriceChangeDetails:
    # New recurring price for the subscription item.
    new_price: GoogleMoney
    # Price change mode specifies how the subscription item price is changing.
    price_change_mode: SubscriptionV2SubscriptionItemPriceChangeDetailsModeType
    # State the price change is currently in.
    price_change_state: SubscriptionV2SubscriptionItemPriceChangeDetailsStateType
    # The renewal time at which the price change will become effective for the user. This is subject to change(to a future time) due to cases where the renewal time shifts like pause. This field is only populated if the price change has not taken effect.
    # Uses RFC 3339, where generated output will always be Z-normalized and use 0, 3, 6 or 9 fractional digits. Offsets other than "Z" are also accepted. Examples: "2014-10-02T15:01:23Z", "2014-10-02T15:01:23.045123456Z" or "2014-10-02T15:01:23+05:30".
    expected_new_price_charge_time: GoogleTimestamp

class SubscriptionV2SubscriptionPriceConsentStateType(StrEnum):
    # Unspecified consent state.
    CONSENT_STATE_UNSPECIFIED = "CONSENT_STATE_UNSPECIFIED"
    # The user has not yet provided consent.
    PENDING = "PENDING"
    # The user has consented, and the new price is waiting to take effect.
    CONFIRMED = "CONFIRMED"
    # The user has consented, and the new price has taken effect.
    COMPLETED = "COMPLETED"


@dataclasses.dataclass
class SubscriptionV2SubscriptionItemInstallmentPlanPendingCancellation:
    state: SubscriptionV2SubscriptionPriceConsentStateType
    # The deadline by which the user must provide consent. If consent is not provided by this time, the subscription will be canceled.
    # Uses RFC 3339, where generated output will always be Z-normalized and use 0, 3, 6 or 9 fractional digits. Offsets other than "Z" are also accepted. Examples: "2014-10-02T15:01:23Z", "2014-10-02T15:01:23.045123456Z" or "2014-10-02T15:01:23+05:30".
    consent_deadline_time: GoogleTimestamp
    new_price: GoogleMoney

@dataclasses.dataclass
class SubscriptionV2SubscriptionItemInstallmentPlan:
    # Total number of payments the user is initially committed for.
    initial_committed_payments_count: int
    # Total number of payments the user will be committed for after each commitment period. Empty means the installment plan will fall back to a normal auto-renew subscription after initial commitment.
    subsequent_committed_payments_count: int
    # Total number of committed payments remaining to be paid for in this renewal cycle.
    remaining_committed_payments_count: int
    # If present, this installment plan is pending to be canceled. The cancellation will happen only after the user finished all committed payments.
    pending_cancellation: Optional[SubscriptionV2SubscriptionItemInstallmentPlanPendingCancellation]


@dataclasses.dataclass
class SubscriptionV2DataAutoRenewingPlan:
    # If the subscription is currently set to auto-renew, e.g. the user has not canceled the subscription
    auto_renew_enabled: bool
    # The current recurring price of the auto renewing plan. Note that the price does not take into account discounts and does not include taxes for tax-exclusive pricing, please call orders.get API instead if transaction details are needed.
    recurring_price: GoogleMoney
    # The information of the last price change for the item since subscription signup.
    price_change_details: Optional[SubscriptionV2SubscriptionItemPriceChangeDetails]
    # The installment plan commitment and state related info for the auto renewing plan.
    installment_details: Optional[SubscriptionV2SubscriptionItemInstallmentPlan]
    # The information of the latest price step-up consent.
    price_step_up_consent_details: Optional[SubscriptionV2SubscriptionPriceConsentStateType]

@dataclasses.dataclass
class SubscriptionV2DataPrepaidPlan:
    # If present, this is the time after which top up purchases are allowed for the prepaid plan. Will not be present for expired prepaid plans.
    # Uses RFC 3339, where generated output will always be Z-normalized and use 0, 3, 6 or 9 fractional digits. Offsets other than "Z" are also accepted. Examples: "2014-10-02T15:01:23Z", "2014-10-02T15:01:23.045123456Z" or "2014-10-02T15:01:23+05:30".
    allow_extend_after_time: GoogleTimestamp

@dataclasses.dataclass
class SubscriptionV2DataOfferDetails:
    # The latest offer tags associated with the offer. It includes tags inherited from the base plan.
    offer_tags: list[str]
    # The base plan ID. Present for all base plan and offers.
    base_plan_id: str
    # The offer ID. Only present for discounted offers.
    offer_id: Optional[str]

@dataclasses.dataclass
class SubscriptionV2DataDeferredItemReplacement:
    # The productId going to replace the existing productId.
    product_id: str

@dataclasses.dataclass
class SubscriptionV2DataSignupPromotionVanityCode:
    promotion_code: str

@dataclasses.dataclass
class SubscriptionV2DataSignupPromotion:
    """
    Only one of these two fields can exist at the same time.
    """
    # A one-time code was applied. (empty object bool)
    one_time_code: bool
    # A vanity code was applied.
    vanity_code: Optional[SubscriptionV2DataSignupPromotionVanityCode]

@dataclasses.dataclass
class SubscriptionV2DataLineItem:
    """
    Only one of the following plan_type objects can exist:
    - auto_renewing_plan
    - prepaid_plan

    Only one of the following deferred_item_change objects can exist, they only exist when an item has a deferred change:
    - deferred_item_replacement
    - deferred_item_removal
    - signup_promotion
    """
    # The purchased product ID (for example, 'monthly001').
    product_id: str
    # Time at which the subscription expired or will expire unless the access is extended (ex. renews).
    # Uses RFC 3339, where generated output will always be Z-normalized and use 0, 3, 6 or 9 fractional digits. Offsets other than "Z" are also accepted. Examples: "2014-10-02T15:01:23Z", "2014-10-02T15:01:23.045123456Z" or "2014-10-02T15:01:23+05:30".
    expiry_time: GoogleTimestamp
    # The order id of the latest successful order associated with this item. Not present if the item is not owned by the user yet (e.g. the item being deferred replaced to).
    latest_successful_order_id: Optional[str]
    # The item is auto renewing.
    auto_renewing_plan: Optional[SubscriptionV2DataAutoRenewingPlan]
    # The item is prepaid.
    prepaid_plan: Optional[SubscriptionV2DataPrepaidPlan]
    # The offer details for this item.
    offer_details: SubscriptionV2DataOfferDetails
    # Information for deferred item replacement.
    deferred_item_replacement: Optional[SubscriptionV2DataDeferredItemReplacement]
    # Information for deferred item removal. (empty object)
    deferred_item_removal: Optional[dict]
    # Promotion details about this item. Only set if a promotion was applied during signup.
    signup_promotion: Optional[SubscriptionV2DataSignupPromotion]

@dataclasses.dataclass
class SubscriptionV2ExternalAccountIdentifiers:
    """User account identifier in the third-party service."""
    # User account identifier in the third-party service. Only present if account linking happened as part of the subscription purchase flow.
    external_account_id: str
    # An obfuscated version of the id that is uniquely associated with the user's account in your app. Present for the following purchases: * If account linking happened as part of the subscription purchase flow. * It was specified using https://developer.android.com/reference/com/android/billingclient/api/BillingFlowParams.Builder#setobfuscatedaccountid when the purchase was made.
    obfuscated_external_account_id: str
    # An obfuscated version of the id that is uniquely associated with the user's profile in your app. Only present if specified using https://developer.android.com/reference/com/android/billingclient/api/BillingFlowParams.Builder#setobfuscatedprofileid when the purchase was made.
    obfuscated_external_profile_id: str

@dataclasses.dataclass
class SubscriptionV2SubscribeWithGoogleInfo:
    """Information associated with purchases made with 'Subscribe with Google'."""
    # The Google profile id of the user when the subscription was purchased.
    profile_id: str
    # The profile name of the user when the subscription was purchased.
    profile_name: str
    # The email address of the user when the subscription was purchased.
    email_address: str
    # The given name of the user when the subscription was purchased.
    given_name: str
    # The family name of the user when the subscription was purchased.
    family_name: str

@dataclasses.dataclass
class SubscriptionV2Data:
    """
    Indicates the status of a user's subscription purchase.

    NOTE: unused fields are commented out.
    """
    # This kind represents a SubscriptionPurchaseV2 object in the androidpublisher service.
    kind: str

    # ISO 3166-1 alpha-2 billing country/region code of the user at the time the subscription was granted.
    # region_code: str

    # Item-level info for a subscription purchase. The items in the same purchase should be either all with AutoRenewingPlan or all with PrepaidPlan.
    line_items: list[SubscriptionV2DataLineItem]

    # Time at which the subscription was granted. Not set for pending subscriptions (subscription was created but awaiting payment during signup).
    # Uses RFC 3339, where generated output will always be Z-normalized and use 0, 3, 6 or 9 fractional digits. Offsets other than "Z" are also accepted. Examples: "2014-10-02T15:01:23Z", "2014-10-02T15:01:23.045123456Z" or "2014-10-02T15:01:23+05:30".
    start_time: GoogleTimestamp

    # The current state of the subscription.
    subscription_state: SubscriptionsV2SubscriptionStateType

    # The purchase token of the old subscription if this subscription is one of the following: * Re-signup of a canceled but non-lapsed subscription * Upgrade/downgrade from a previous subscription. * Convert from prepaid to auto renewing subscription. * Convert from an auto renewing subscription to prepaid. * Topup a prepaid subscription.
    linked_purchase_token: Optional[str]

    # Additional context around paused subscriptions. Only present if the subscription currently has subscriptionState SUBSCRIPTION_STATE_PAUSED.
    paused_state_context: Optional[SubscriptionsV2SubscriptionPausedStateContext]

    # Additional context around canceled subscriptions. Only present if the subscription currently has subscriptionState SUBSCRIPTION_STATE_CANCELED or SUBSCRIPTION_STATE_EXPIRED.
    canceled_state_context: Optional[SubscriptionsV2SubscriptionCanceledStateContext]

    # Only present if this subscription purchase is a test purchase. (empty object bool)
    test_purchase: bool

    # The acknowledgement state of the subscription.
    acknowledgement_state: SubscriptionsV2SubscriptionAcknowledgementStateType

    # User account identifier in the third-party service.
    # external_account_identifiers: SubscriptionV2ExternalAccountIdentifiers

    # User profile associated with purchases made with 'Subscribe with Google'.
    # subscribe_with_google_info:  SubscriptionV2SubscribeWithGoogleInfo


def json_dict_require_google_money(d: dict[str, base.JSONValue], key: str, err: base.ErrorSink):
    price_obj = base.json_dict_require_obj(d, key, err)

    currency_code = base.json_dict_require_str(price_obj, "currencyCode", err)
    units = base.json_dict_require_str(price_obj, "units", err)
    nanos = base.json_dict_require_int(price_obj, "nanos", err)

    return GoogleMoney(currency_code=currency_code, units=units, nanos=nanos)

def json_dict_require_google_timestamp(d: dict[str, base.JSONValue], key: str, err: base.ErrorSink):
    timestamp_str = base.json_dict_require_str(d, key, err)

    return GoogleTimestamp(timestamp_str, err)

def json_dict_optional_google_empty_object_bool(d: dict[str, base.JSONValue], key: str, err: base.ErrorSink) -> bool:
    result = False
    if key in d:
        v = None
        if isinstance(d[key], dict):
            v = typing.cast(dict[str, base.JSONValue], d[key])
        else:
            err.msg_list.append(f'Key "{key}" value was not an object: "{base.safe_get_dict_value_type(d, key)}"')
        if v is not None and len(v.keys()) == 0:
            result = True
        else:
            err.msg_list.append(f'Key "{key}" value was not a google empty object: "{base.safe_get_dict_value_type(d, key)}"')
    return result
