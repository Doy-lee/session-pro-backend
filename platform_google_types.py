'''
Type definitions for data structures used in the Google APIs
'''

import dataclasses
import traceback
import typing
from enum import IntEnum, StrEnum
import typing_extensions

from google.protobuf.internal.well_known_types import Timestamp

import base

# RFC 3339, where generated output will always be Z-normalized and use 0, 3, 6 or 9 fractional
# digits. Offsets other than "Z" are also accepted. Examples: "2014-10-02T15:01:23Z",
# "2014-10-02T15:01:23.045123456Z" or "2014-10-02T15:01:23+05:30".
@dataclasses.dataclass
class GoogleTimestamp(Timestamp):
    rfc3339:           str = ''
    unix_milliseconds: int = 0
    unix_seconds:      int = 0

    def __init__(self, rfc3339_timestamp: str, err: base.ErrorSink):
        self.rfc3339 = rfc3339_timestamp
        try:
            self.FromJsonString(rfc3339_timestamp)
            self.unix_milliseconds = self.ToMilliseconds()
            self.unix_seconds = self.ToSeconds()

        except Exception as e:
            err.msg_list.append(f'Failed to parse timestamp "{rfc3339_timestamp}": {traceback.format_exc()}')

    @typing_extensions.override
    def __repr__(self):
        return f"GoogleTimestamp('{self.rfc3339}', unix={self.unix_seconds})"

# Copied from google.protobuf.internal.well_known_types
_DURATION_SECONDS_MAX = 315576000000

class GoogleDuration():
    iso8601: str
    seconds: int
    milliseconds: int

    def __init__(self, iso8601_duration: str, err: base.ErrorSink):
        self.iso8601 = iso8601_duration
        try:
            self.seconds = self.FromJsonString(iso8601_duration)
            if self.seconds > _DURATION_SECONDS_MAX:
                raise ValueError(f"Duration too long! {self.seconds} > {_DURATION_SECONDS_MAX}")
            self.milliseconds = self.seconds * 1000
        except Exception as e:
            err.msg_list.append(f'Failed to parse duration "{iso8601_duration}: {traceback.format_exc()}"')

    @typing_extensions.override
    def __repr__(self):
        return f"GoogleDuration('{self.iso8601}', ms={self.milliseconds})"

    def FromJsonString(self, value: str) -> int:
        """Parse a ISO 8601 Duration string format to a Duration.
        NOTE: this parser is not fully compliant with ISO 8601, it is intended for use
        with google's protobuf duration value.

        Args:
          value (str): An ISO 8601 duration string. Example of accepted format: 'P3M'

        Raises:
          ValueError: On parsing problems.
        """
        if not isinstance(value, str):
          raise ValueError(f'Duration JSON value not a string: {value}')

        if len(value) < 3 or value[0] != 'P':
            raise ValueError(f'Duration is not correct ISO 8601 format: {value}')
        
        seconds_multiplier = 0
        buffer_units = ''
        duration_seconds = 0
        in_time_component = False
        for c in value:
            commit = True
            match c:
                case 'Y':
                    seconds_multiplier = base.SECONDS_IN_YEAR
                case 'M':
                    if in_time_component:
                        seconds_multiplier = 60
                    else:
                        seconds_multiplier = base.SECONDS_IN_MONTH
                case 'W':
                    seconds_multiplier = base.SECONDS_IN_DAY * 7
                case 'D':
                    seconds_multiplier = base.SECONDS_IN_DAY
                case 'P':
                    seconds_multiplier = 0
                    commit = False
                case 'T':
                    seconds_multiplier = 0
                    commit = False
                    in_time_component = True
                case 'H':
                    if not in_time_component:
                        raise ValueError("Attempted to parse a time value outside of an ISO 8601 time component")
                    seconds_multiplier = 60 * 60
                case 'S':
                    if not in_time_component:
                        raise ValueError("Attempted to parse a time value outside of an ISO 8601 time component")
                    seconds_multiplier = 1
                case _:
                    if not c.isdigit():
                        raise ValueError(f"Attempted to parse an illegal character: {c}")
                    buffer_units += c
                    commit = False

            if commit:
                    duration_seconds += int(buffer_units) * seconds_multiplier
                    buffer_units = ''
                    seconds_multiplier = 0

        return duration_seconds


class SubscriptionNotificationType(IntEnum):
    NIL                           = 0 # Sentinel value, never used except for zero-initialised objects
    RECOVERED                     = 1 # Recovered from account hold.
    RENEWED                       = 2 # Active subscription was renewed.
    CANCELED                      = 3 # Subscription was in/voluntarily cancelled. It is voluntary if the user cancels.
    PURCHASED                     = 4 # New subscription was purchased.
    ON_HOLD                       = 5 # Subscription has entered account hold (if enabled).
    IN_GRACE_PERIOD               = 6 # Subscription has entered grace period (if enabled).
    # User has restored their subscription from Play > Account > Subscriptions. The subscription was
    # canceled but had not expired yet when the user restores. For more information, see
    # Restorations.
    RESTARTED                     = 7
    PRICE_CHANGE_CONFIRMED        = 8  # @deprecated Subscription price change has successfully been confirmed by the user.
    DEFERRED                      = 9  # Subscription's recurrence time has been extended.
    PAUSED                        = 10 # Subscription has been paused.
    PAUSE_SCHEDULE_CHANGED        = 11 # Subscription pause schedule has been changed.
    REVOKED                       = 12 # Subscription has been revoked from the user before the expiration time.
    EXPIRED                       = 13 # Subscription has expired.
    PRICE_CHANGE_UPDATED          = 19 # Subscription item's price change details are updated.
    PENDING_PURCHASE_CANCELED     = 20 # Pending transaction of a subscription has been canceled.
    # A subscription's consent period for price step-up has begun or the user has provided consent
    # for the price step-up. This RTDN is sent only for subscriptions in a region where price
    # step-up is required.
    PRICE_STEP_UP_CONSENT_UPDATED = 22

class ProductType(IntEnum): # Product types for voided purchases
    NIL          = 0 # Sentinel value, never used except for zero-initialised objects
    SUBSCRIPTION = 1 # A subscription purchase has been voided.
    ONE_TIME     = 2 # A one-time purchase has been voided.

class RefundType(IntEnum): # Refund types for voided purchases
    NIL                           = 0 # Sentinel value, never used except for zero-initialised objects
    FULL_REFUND                   = 1
    # The purchase has been partially voided by a quantity-based partial refund, applicable only to
    # multi-quantity purchases. A purchase can be partially voided multiple times.
    QUANTITY_BASED_PARTIAL_REFUND = 2

class SubscriptionsV2State(StrEnum):
    """Subscriptions V2 subscription state types"""
    UNSPECIFIED = "SUBSCRIPTION_STATE_UNSPECIFIED"

    # Subscription was created but awaiting payment during signup. In this state, all items are
    # awaiting payment.
    PENDING = "SUBSCRIPTION_STATE_PENDING"

    # - (1) If the subscription is an auto renewing plan, at least one item is autoRenewEnabled and
    #   not expired.
    # - (2) If the subscription is a prepaid plan, at least one item is not expired.
    ACTIVE = "SUBSCRIPTION_STATE_ACTIVE"

    # The state is only available when the subscription is an auto renewing plan, all items are in a
    # paused state.
    PAUSED = "SUBSCRIPTION_STATE_PAUSED"

    # The state is only available when the subscription is an auto renewing plan, all items are in
    # a grace period.
    IN_GRACE_PERIOD = "SUBSCRIPTION_STATE_IN_GRACE_PERIOD"

    # The state is only available when the subscription is an auto renewing plan, all items are on
    # hold.
    ON_HOLD = "SUBSCRIPTION_STATE_ON_HOLD"

    # Subscription is canceled but not expired yet. The state is only available when the
    # subscription is an auto renewing plan, all items have autoRenewEnabled set to false.
    CANCELED = "SUBSCRIPTION_STATE_CANCELED"

    # All -items have expiryTime in the past.
    EXPIRED = "SUBSCRIPTION_STATE_EXPIRED"

    # Pending transaction for subscription is canceled. If this pending purchase was for an existing
    # subscription, use linkedPurchaseToken to get the current state of that subscription.
    PENDING_PURCHASE_CANCELED = "SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED"

class SubscriptionsV2AcknowledgementState(StrEnum):
    """Subscriptions V2 subscription Acknowledgement state types"""
    UNSPECIFIED  = "ACKNOWLEDGEMENT_STATE_UNSPECIFIED"
    PENDING      = "ACKNOWLEDGEMENT_STATE_PENDING"
    ACKNOWLEDGED = "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED"

class SubscriptionsV2UserSurveyResponseReason(StrEnum):
    """The reason the user selected in the cancel survey."""
    UNSPECIFIED      = "UNSPECIFIED"
    NOT_ENOUGH_USAGE = "NOT_ENOUGH_USAGE"
    TECHNICAL_ISSUES = "TECHNICAL_ISSUES"
    COST_RELATED     = "COST_RELATED"
    FOUND_BETTER_APP = "FOUND_BETTER_APP"
    OTHERS           = "OTHERS"

@dataclasses.dataclass
class SubscriptionsV2PausedState:
    """Information specific to a subscription in paused state."""
    auto_resume_time: GoogleTimestamp # Time at which the subscription will be automatically resumed.

@dataclasses.dataclass
class SubscriptionsV2UserSurveyResponse:
    """Result of the cancel survey when the subscription was canceled by the user."""
    reason: SubscriptionsV2UserSurveyResponseReason # The reason the user selected in the cancel survey.
    reason_user_input: str | None # Only set for OTHERS. This is the user's free-form response to the survey.

# TODO: we need to collect cancel reasons
@dataclasses.dataclass
class SubscriptionsV2SubscriptionCanceledStateContextUser:
    cancel_survey_result: SubscriptionsV2UserSurveyResponse | None

    # The time at which the subscription was canceled by the user. The user might still have access
    # to the subscription after this time. Use lineItems.expiry_time to determine if a user still
    # has access.
    cancel_time: GoogleTimestamp

@dataclasses.dataclass
class SubscriptionsV2CanceledState:
    """Only one of the fields will be set at a time"""
    # Subscription was canceled by user.
    user_initiated_cancellation: SubscriptionsV2SubscriptionCanceledStateContextUser | None
    # Subscription was canceled by the system, for example because of a billing problem. (empty object bool)
    system_initiated_cancellation: bool
    # Subscription was canceled by the developer. (empty object bool)
    developer_initiated_cancellation: bool
    # Subscription was replaced by a new subscription. (empty object bool)
    replacement_cancellation: bool


@dataclasses.dataclass
class GoogleMoney:
    currency_code: str # Three-letter currency code defined in ISO 4217
    units: str         # Whole units of the amount. E.g. If currencyCode is "USD", then 1 unit is one US dollar.

    # Number of nano (10^-9) units of the amount. The value must be between -999,999,999 and
    # +999,999,999 inclusive. If units is positive, nanos must be positive or zero. If units is
    # zero, nanos can be positive, zero, or negative. If units is negative, nanos must be negative
    # or zero. For example $-1.75 is represented as units=-1 and nanos=-750,000,000.
    nanos: int

class SubscriptionV2PriceChangeMode(StrEnum):
    # Price change mode unspecified. This value should never be set.
    PRICE_CHANGE_MODE_UNSPECIFIED = "PRICE_CHANGE_MODE_UNSPECIFIED"
    # If the subscription price is decreasing.
    PRICE_DECREASE = "PRICE_DECREASE"
    # If the subscription price is increasing and the user needs to accept it.
    PRICE_INCREASE = "PRICE_INCREASE"
    # If the subscription price is increasing with opt out mode.
    OPT_OUT_PRICE_INCREASE = "OPT_OUT_PRICE_INCREASE"

class SubscriptionV2PriceChangeState(StrEnum):
    PRICE_CHANGE_STATE_UNSPECIFIED = "PRICE_CHANGE_STATE_UNSPECIFIED" # Price change state unspecified. This value should not be used.
    OUTSTANDING                    = "OUTSTANDING"                    # Waiting for the user to agree for the price change.
    CONFIRMED                      = "CONFIRMED"                      # The price change is confirmed to happen for the user.
    APPLIED                        = "APPLIED"                        # The price change is applied, i.e. the user has started being charged the new price.
    CANCELED                       = "CANCELED"

@dataclasses.dataclass
class SubscriptionV2PriceChangeDetails:
    new_price:                      GoogleMoney                    # New recurring price for the subscription item.
    price_change_mode:              SubscriptionV2PriceChangeMode  # Price change mode specifies how the subscription item price is changing.
    price_change_state:             SubscriptionV2PriceChangeState # State the price change is currently in.
    # The renewal time at which the price change will become effective for the user. This is subject
    # to change (to a future time) due to cases where the renewal time shifts like pause. This field
    # is only populated if the price change has not taken effect.
    expected_new_price_charge_time: GoogleTimestamp

class SubscriptionV2PriceConsentState(StrEnum):
    CONSENT_STATE_UNSPECIFIED = "CONSENT_STATE_UNSPECIFIED" # Unspecified consent state.
    PENDING                   = "PENDING"                   # User has not yet provided consent.
    CONFIRMED                 = "CONFIRMED"                 # User has consented, and the new price is waiting to take effect.
    COMPLETED                 = "COMPLETED"                 # User has consented, and the new price has taken effect.


@dataclasses.dataclass
class SubscriptionV2InstallmentPlanPendingCancellation:
    state: SubscriptionV2PriceConsentState

    # The deadline by which the user must provide consent. If consent is not provided by this time,
    # the subscription will be canceled.
    consent_deadline_time: GoogleTimestamp
    new_price: GoogleMoney

@dataclasses.dataclass
class SubscriptionV2InstallmentPlan:
    # Total number of payments the user is initially committed for.
    initial_committed_payments_count: int
    # Total number of payments the user will be committed for after each commitment period. Empty
    # means the installment plan will fall back to a normal auto-renew subscription after initial
    # commitment.
    subsequent_committed_payments_count: int
    # Total number of committed payments remaining to be paid for in this renewal cycle.
    remaining_committed_payments_count: int
    # If present, this installment plan is pending to be canceled. The cancellation will happen only
    # after the user finished all committed payments.
    pending_cancellation: SubscriptionV2InstallmentPlanPendingCancellation | None


@dataclasses.dataclass
class SubscriptionV2DataAutoRenewingPlan:
    auto_renew_enabled: bool
    # The current recurring price of the auto renewing plan. Note that the price does not take into
    # account discounts and does not include taxes for tax-exclusive pricing, please call orders.get
    # API instead if transaction details are needed.
    recurring_price: GoogleMoney
    # The information of the last price change for the item since subscription signup.
    price_change_details:         SubscriptionV2PriceChangeDetails | None
    # The installment plan commitment and state related info for the auto renewing plan.
    installment_details:           SubscriptionV2InstallmentPlan | None
    price_step_up_consent_details: SubscriptionV2PriceConsentState | None

@dataclasses.dataclass
class SubscriptionV2DataPrepaidPlan:
    # If present, this is the time after which top up purchases are allowed for the prepaid plan.
    # Will not be present for expired prepaid plans.
    allow_extend_after_time: GoogleTimestamp

@dataclasses.dataclass
class SubscriptionV2DataOfferDetails:
    offer_tags: list[str] # Latest tags associated with the offer. It includes tags inherited from the base plan.
    base_plan_id: str     # Present for all base plan and offers.
    offer_id: str | None  # Only present for discounted offers.

@dataclasses.dataclass
class SubscriptionV2DataDeferredItemReplacement:
    product_id: str # ID that is going to replace the existing productId

@dataclasses.dataclass
class SubscriptionV2DataSignupPromotionVanityCode:
    promotion_code: str

@dataclasses.dataclass
class SubscriptionV2DataSignupPromotion:
    """Only one of these two fields can exist at the same time."""
    one_time_code: bool                                               # A one-time code was applied. (empty object bool)
    vanity_code:   SubscriptionV2DataSignupPromotionVanityCode | None # A vanity code was applied.

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
    product_id:                 str

    # Timestamp of when the subscription will expire/renew
    expiry_time:                GoogleTimestamp

    # Purchase order ID, it is not set if the item is not owned by the user yet (e.g. the item being
    # deferred/replaced to).
    latest_successful_order_id: str                                       | None
    auto_renewing_plan:         SubscriptionV2DataAutoRenewingPlan        | None
    prepaid_plan:               SubscriptionV2DataPrepaidPlan             | None
    offer_details:              SubscriptionV2DataOfferDetails
    deferred_item_replacement:  SubscriptionV2DataDeferredItemReplacement | None

    # Information for deferred item removal. (empty object)
    deferred_item_removal:      dict | None

    # Only set if a promotion was applied during signup.
    signup_promotion:           SubscriptionV2DataSignupPromotion | None

@dataclasses.dataclass
class SubscriptionV2Data:
    """Status of a user's subscription purchase."""
    # This kind represents a SubscriptionPurchaseV2 object in the androidpublisher service.
    kind: str = ''

    # Item-level info for a subscription purchase. The items in the same purchase should be either all with AutoRenewingPlan or all with PrepaidPlan.
    line_items: list[SubscriptionV2DataLineItem] = dataclasses.field(default_factory=list)

    # Time at which the subscription was granted. Not set for pending subscriptions (subscription
    # was created but awaiting payment during signup).
    start_time:             GoogleTimestamp | None = None
    subscription_state:     SubscriptionsV2State   = SubscriptionsV2State.UNSPECIFIED

    # The purchase token of the old subscription if this subscription is one of the following:
    # - Re-signup of a canceled but non-lapsed subscription 
    # - Upgrade/downgrade from a previous subscription.
    # - Convert from prepaid to auto renewing subscription.
    # - Convert from an auto renewing subscription to prepaid.
    # - Topup a prepaid subscription.
    linked_purchase_token:  str | None = None

    # Paused metadata, set if `subscription_state` is `SUBSCRIPTION_STATE_PAUSED`
    paused_state_context:   SubscriptionsV2PausedState | None = None

    # Cancel metaddata, set if `subscription_state` is `SUBSCRIPTION_STATE_CANCELED` or
    # `SUBSCRIPTION_STATE_EXPIRED`.
    canceled_state_context: SubscriptionsV2CanceledState | None = None

    test_purchase:          bool = False # Set if this subscription purchase is a test purchase

    acknowledgement_state:  SubscriptionsV2AcknowledgementState = SubscriptionsV2AcknowledgementState.UNSPECIFIED

@dataclasses.dataclass
class Monetizationv3SubscriptionData:
    """
    NOTE: only the fields we use are here, the api returns loads of other info we dont need.
    """
    base_plans: base.JSONArray

@dataclasses.dataclass
class SubscriptionProductDetails:
    billing_period: GoogleDuration # Subscription duration
    grace_period:   GoogleDuration # Duration of entitlement an auto-renewing subscription has after it expires

def json_dict_require_google_money(d: dict[str, base.JSONValue], key: str, err: base.ErrorSink):
    price_obj = base.json_dict_require_obj(d, key, err)

    currency_code = base.json_dict_require_str(price_obj, "currencyCode", err)
    units = base.json_dict_require_str(price_obj, "units", err)
    nanos = base.json_dict_require_int(price_obj, "nanos", err)

    return GoogleMoney(currency_code=currency_code, units=units, nanos=nanos)

def json_dict_require_google_timestamp(d: dict[str, base.JSONValue], key: str, err: base.ErrorSink):
    timestamp_str = base.json_dict_require_str(d, key, err)
    return GoogleTimestamp(timestamp_str, err)


def json_dict_require_google_duration(d: dict[str, base.JSONValue], key: str, err: base.ErrorSink):
    duration_str = base.json_dict_require_str(d, key, err)
    return GoogleDuration(duration_str, err)


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
