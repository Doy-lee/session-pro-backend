# Google Platform

## Refunds

The Google Play store subscriptions have two types of refunds:
1. Google refunds, which can only happen within 48 hours of a purchase.
2. Developer refunds, which can happen at any time.

Typically apps direct users to request refunds via Google if is has been less than 48 hours since the purchase,
then direct users to their own app support channels if its been more than 48 hours since the purchase.

The backend stores a `platform_refund_expiry_ts_ms` timestamp to indicate what time a user's subscription is no
longer eligible for a Google refund. After this time user should be directed to app support.

## Real Time Developer Notifications

Whenever a monetization event happens the google RTDN (Real Time Developer Notification) service
sends a notification to the backend.

There are four types of notifications:

1. Subscription
2. One Time Product
3. Voided Purchase
4. Test

The backend currently supports Subscription (1) and Voided Purchase (3) notifications.

### Subscription

Subscription notifications inform the backend of any state changes to a users subscriptions, including
the creation of new subscriptions.

See [Subscription Lifecycle](#Subscription-Lifecycle)

### One Time Product

One Time Products are not supported.

### Voided Purchase



### Test

Basic test notifications sent via the "Send Test Notification" button on the Monetization Setup page:
```
https://play.google.com/console/u/0/developers/<project-id>/app/<app-id>/monetization-setup
```

## Subscription Lifecycle

This section follows the structure of 
[Google's Subscription Lifecycle Documentation](https://developer.android.com/google/play/billing/lifecycle/subscriptions)
and documents how the backend reacts to each google event.

Notifications from Google's RTDN service provide the backend with hints about a subscription state, they
tell the backend that a subscription has undergone a state change but they don't provide the latest
subscription state. Whenever a notification is received, a request is made for the latest
[Subscription Resource](https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.subscriptionsv2)
this contains the latest state of the subscription.

Each lifecycle stage has a short code block showing the notification state (state from the RTDN service)
and the required subscription state (state from the Subscription Resource) to process the notification.

### Purchase

```
Notification = SUBSCRIPTION_PURCHASED
Subscription = SUBSCRIPTION_STATE_ACTIVE
```

A purchase event happens whenever a new subscription is purchased. This only applies
to "new subscribers".

A **new subscriber** is either a user who:
- purchased a subscription for the first time.
- has subscription in the past that is expired.

For the purposes of determining a new subscription, expired means either the user:
- cancelled their subscription and the expiry time has passed.
- had payment issues with their subscription and it has passed the account hold period.

A new subscription also means changing from one plan to another. Eg: Moving from a
one-month plan to a three-month plan.

A purchase can also include a linked purchase token. If this is present in a purchase
event it means the backend should revoke the subscription linked to the previous
purchase token (the linked purchase token). This may happen if a user moves plans.

When a new subscription is received an unredeemed payment is added to the database. An
unredeemed payment can be redeemed by the user to generate a pro proof.

#### Unredeemed Payment

The following is added to the unredeemed payments table:
- `order_id`
- `purchase_token`
- `provider`
- `expiry_unix_ts_ms`
- `plan`
- `platform_refund_expiry_unix_ts_ms`

### Renewals

```
Notification = SUBSCRIPTION_RENEWED
Subscription = SUBSCRIPTION_STATE_ACTIVE
```

A renew event happens when a non-new subscription purchase happens.

This happens when a subscription:
- reaches the end of its billing duration (expiry time) and
    payment is successfully charged to the user's payment method.
- is in its grace period and the user's payment method is successfully charged.
- is in an account hold period and the user's payment method is successfully charged.

When a renewed subscription is received an unredeemed payment is added to the database.
This unredeemed payment can be redeemed by the user to generate a pro proof.
See [Unredeemed Payment](#Unredeemed-Payment)

### Grace Period

```
Notification = SUBSCRIPTION_IN_GRACE_PERIOD
Subscription = SUBSCRIPTION_STATE_IN_GRACE_PERIOD
```

A grace period event happens when a user's subscription has payment issues
during renewal. During the grace period the user retains their subscription
entitlements.

A subscription only has a grace period if it is set to auto-renew. This means
subscriptions that have been cancelled don't have a grace period, as they
do not auto-renew.

**Because the existence of a grace period on a user's subscription is known
at the time the user's subscription renews, this event can be ignored. If a
user enters a grace period they can request a grace period proof from the
backend, the backend will sign these proofs as long as the user's subscription
has its grace period enabled. The grace period is enabled as long as the user
has not cancelled their subscription.**

**The grace period must be at least 1 day, otherwise google will enforce a
[Silent Grace Period](https://developer.android.com/google/play/billing/lifecycle/subscriptions#silent-grace-period)**

### Account Hold

```
Notification = SUBSCRIPTION_ON_HOLD
Subscription = SUBSCRIPTION_STATE_ON_HOLD
```

An account hold event happens after a [grace period](#Grace-Period) has ended
without a valid payment going through.

**Because the backend issues proofs that expire at a pre-determined time, if
the user transitions from a grace period to an account hold period they won't
be able to request a new proof, as they are no longer in a grace period.**

### Account Hold Recovered

```
Notification = SUBSCRIPTION_RECOVERED
Subscription = SUBSCRIPTION_STATE_ACTIVE
```

An account hold recovered event happens if during an account hold the user's
payment method succeeds.

When a recovered subscription is received an unredeemed payment is added to the database.
This unredeemed payment can be redeemed by the user to generate a pro proof.
See [Unredeemed Payment](#Unredeemed-Payment)

### Cancellations

```
Notification = SUBSCRIPTION_CANCELED
Subscription = SUBSCRIPTION_STATE_CANCELED
```

A cancel event happens when an subscription is canceled. This means it will
not auto-renew.

This can happen because the subscription has been:
- canceled by the user
- canceled by the developer

Cancellation has no effect on entitlement, a subscription can only be canceled
if it is active, or in account hold.
- If it is active, the backend will update the grace period in the database
    to 0, this tells the user their subscription will not renew. **This has
    no effect on the Pro Proof**
- If it is in account hold the backend ignores the event, as the pro proof has
    already expired at this stage.

Users can specify a cancellation reason, this information is stored in the database. 

### Cancellation Reversions (Restart)

```
Notification = SUBSCRIPTION_RESTARTED
Subscription = SUBSCRIPTION_STATE_ACTIVE
```

The restarted event happens when a user resubscribes to their canceled subscription. 
(Eg: clicks "Resubscribe" after canceling)

The restarted event has no effect on entitlement. When this event is received
the backend will update the grace period in the database, indicating to the user
this subscription will auto-renew. This will also allow the user to request a grace
period proof if they enter a grace period after their subscription expires.

**Google allows a user to "Resubscribe" after a subscription is expired, this is
unrelated to the restarted state, even though from the users perspective this is
the same action. When a user resubscribes after their subscription is expired, the
subscription is treated as a new purchase and the `SUBSCRIPTION_PURCHASED` event
is triggered. This issues the user with a new purchase token and does not make
use of the `linkedPurchaseToken` mechanism.**

### Expirations

```
Notification = SUBSCRIPTION_EXPIRED
Subscription = SUBSCRIPTION_STATE_EXPIRED
```

An expired event happens when:
- a subscription expiry time has passed and the subscription was previously
cancelled (not set to auto-renew).
- an on-hold subscription passes its hold period.

**Because Pro Proofs are set to expire on their own at the expire time, there
is no need to make changes to entitlement when the expired event is received.**

### Revocations

```
Notification = SUBSCRIPTION_REVOKED
Subscription = SUBSCRIPTION_STATE_EXPIRED
```

A revoked event happens if a subscription is revoked. This can happen for a
number of reasons including but not limited to:
- The developer revoking a subscription
- Google revoking a subscription
- The subscription payment being charged back

When a revoked event is received the subscription's Pro Proof is immediately
revoked, removing the user's entitlement.

### Price Change Updated



### Price Change Confirmed



### Price Step Up Consent Updated



### Unsupported Events

The following subscription events are not supported by the backend, as such,
all subscriptions plans for the application must not have them enabled:

- SUBSCRIPTION_DEFERRED
- SUBSCRIPTION_PAUSED
- SUBSCRIPTION_PAUSE_SCHEDULE_CHANGED

### Error Handling

To ensure event order consistency, when an RTDN notification encounters an error, the
notification's purchase token is added to an error table.
- any future notifications for that purchase token are ignored and not acknowledged
- any user requests involving that purchase token return an error message

These errors require developer intervention and will be cleared up automatically
once the problem code is fixed. 

## Price Changes

### Price Changes For New Purchases

Once a price change is made, the new price takes effect within a few hours for all new purchases.

### Pricing Cohorts

Active subscriptions with the same purchase price are part of a pricing cohort, when
a price change is made, that cohort does not automatically follow the new price. All
active subscriptions are placed into cohorts with their peers (subscriptions of the same
plan id and region pricing).

For example: If an app has 7 users on a 1 month plan (5 in Switzerland and 2 
in Germany), and 2 users on the 3 month plan (1 in Switzerland and 1 in France). The
app has 4 active price cohorts:

1. 5 users paying Switzerland pricing for the 1 month plan
2. 2 users paying Germany pricing for the 1 month plan
3. 1 user paying Switzerland pricing for the 3 month plan
4. 1 user paying Germany pricing for the 3 month plan

If the developer changes increases the price for the 1 month plan, cohort 1 and 2
will both become legacy cohorts, meaning no other users can join that cohort. The
users in cohort 1 and cohort 2 will continue paying their initial subscription
purchase price.

At any time after a subscription price change, the developer can end a "Legacy
Price Cohort", this will trigger a migration for users in the legacy cohort
to the active cohort for their region and plan type.

#### Price Increase

For a price increase, ending a legacy price cohort will trigger a RTDN notification
to the backend for every subscription in that cohort. This starts a series of events.

In most regions price increases are defaulted to opt-in. Users are given a minimum
notice period of 37 days, and are only notified by google 30 days before the price
increase.

For a one-month subscription, this means 37 days after the legacy price cohort is
ended, all users in that cohort are either on the new pricing or no longer subscribed.

For a one-year subscriptions, this means 372 days after the legacy price cohort
is ended, all users in that cohort are either on the new pricing or no longer subscribed.

1. **+0 days** | The developer has been notified of a subscriptions legacy price
    cohort ending. The developer has 7 days to inform the user of this price change
    through the app UI.
2. **+7 days** | Google Play starts notifying each user of the price change 30 days
    before the first renewal with the new price.

If a user opts-in to the price change, a RTDN notification will tell the backend 
the price has been accepted. This will be reflected in the database.

If a user opts-out to the price change, a RTDN notification will tell the backend
the price has been rejected, canceling the plan, meaning it won't auto-renew.

