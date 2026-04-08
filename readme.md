# Session Pro Backend

A server powered by Python3 and Flask to manage the lifetime of a Session
Pro subscription for Session users such as:

- Registering payments for Session Pro subscriptions
- Producing cryptographic proofs to entitle cryptographic keys to use Session Pro
  features on the Session protocol
- Pruning expired and revoking cryptographic proofs
- Authorising new cryptographic keys for a pre-existing subscription

And so forth.

# Layout

- `vendor/`: 3rd party dependencies

- `examples/`: Helper script to contact all the endpoints of a Pro Backend
  development server dumping the JSON requests and responses for said endpoints.

- `base.py`: Basic primitives shared across all modules where necessary.

- `backend.py`: DB layer that validates incoming requests and stores/retrieves
information from the DB.

- `main.py`: Entry point of application that setups the basic environment for the
database and then hands over control flow to Flask to handle HTTP requests.

- `cli.py`: Command-line interface for database operations. Use this for user error
  management, Google notification handling, revocations, report generation, and DB
  inspection. Run `python cli.py --help` for detailed usage information.

- `platform_apple.py`: iOS App Store layer that exposes a HTTP route to receive
  subscription purchases and convert it into a Session Pro Proof.

- `platform_google*.py`: Google Play Store layer that subscribes to Google
services to witness subscription purchases and convert it into a Session Pro
Proof.

- `server.py`: HTTP layer that parses client requests and forwards them to backend
layer and replies a response, if any.

- `test.py`: Holds the unit tests implemented via pytest.

## Getting Started

```
[base]
# Database connection URL. Supports SQLite and PostgreSQL:
#   SQLite:     sqlite:///path/to/database.db    (relative path, 3 slashes)
#               sqlite:////absolute/path/db.db   (absolute path, 4 slashes)
#   PostgreSQL: postgresql://user:password@host:port/database
db_url                       = sqlite:///backend.db

# Set the path where logs and rotated logs will be stored (omit this value/line to opt out of
# logging to a file completely)
log_path                     = <path/to/log>

# Start the server in developer mode, this is most likely only interesting if
# you are developing locally. If the DB hasn't been bootstrapped yet, this
# causes the backend to generate a deterministic secret Ed25519 key with 32 bytes of 0xCD
# and hence creates the following key pairs:
#
#   Secret: 0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
#   Public: 0xfc947730f49eb01427a66e050733294d9e520e545c7a27125a780634e0860a27
#
# If the DB already exists this won't have any effect as it will not overwrite
# the existing DB.
dev                          = false

# Enable pulling subscription purchases from the iOS App Store. The [apple] section must be
# configured if this is set
with_platform_apple          = false

# Enable pulling subscription purchases from the Google Play Store. The [google] section must be
# configured if this is set
with_platform_google         = false

# Turn this on if you intend to pull test-notifications from Google/Apple and work with subscription
# payments that have a modified duration (e.g. Google modifies a 1-day subscription to 10 seconds). This
# will modify some functionality with event timestamps to ensure that these timespans are respected
#
# One example is rounding timestamps to Google/Apple's modified timespan to determine whether or not
# a revocation overlaps with the expiry of a payment. If there's an overlap the backend can skip
# issuing a revocation (which is an expensive operation).
platform_testing_env         = false

# By default the backend is configured to strip personal-identifying information (PII) from the
# logs. Enabling this preserves all information in logs. This should not be used in a
# production use-case.
unsafe_logging               = false

# Set the URL to the Session Webhook Manage URL to push warning and error logs to at runtime. Each
# subsequent webhook should be in a section with consecutive incrementing indexes. Omit this
# section to opt out

# [session_webhook.0]
# enabled = False
# url     = <url...>
# name    = <display name...>

# NOTE: The [apple] section and its fields are only required if `with_platform_apple` is defined
[apple]

# Platform specific strings, see:
# https://github.com/apple/app-store-server-library-python?tab=readme-ov-file#api-usage
key_id                       = <string: key_id>    # e.g. ABCDEFGHIJ
issuer_id                    = <string: issuer_id> # e.g. aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
bundle_id                    = <string: bundle_id> # e.g. com.company.my_application

key_path                     = <string: path/to/keys.p8>
root_cert_path               = <string: path/to/AppleIncRootCertificate.cer>
root_cert_ca_g2_path         = <string: path/to/AppleRootCA-G2.cer>
root_cert_ca_g3_path         = <string: path/to/AppleRootCA-G3.cer>

# Run in Apple's Sandbox environment, otherwise production
sandbox_env                  = true

# This is required if running in production mode (i.e. `sandbox_env` is set to false), otherwise we are
# unable to start up Apple's library
app_id                       = <int: app_id>

# NOTE: The [google] section and its fields are only required if `with_platform_google` is defined
[google]
package_name                 = <string: package_name> # e.g. com.company.my_application

# Name of the product to handle Google Play notifications from
subscription_product_id      = session_pro

# Google cloud project that is authorised to receive billing notifications from the google play app
cloud_project_id             = <string: project_name> # e.g. company-ABCDE

# Name of the Google cloud subscription to query notifications from
cloud_subscription_name      = session-pro-sub

# Google cloud application credentials .JSON file
cloud_app_credentials_path   = <path/to/credentials>.json
```

A subset of the options specifiable by the .INI file can be overridden using
environment variables with the exception of `SESH_PRO_BACKEND_INI_PATH` which
can only be specified as an environment variable.

```
# Path to load the .INI file and hence the options to customise the runtime behaviour
SESH_PRO_BACKEND_INI_PATH=<path/to/ini/file.ini>

# For the following options, see the .INI section for more information
SESH_PRO_BACKEND_DB_URL                  = <...>
SESH_PRO_BACKEND_LOG_PATH                = <...>
SESH_PRO_BACKEND_DEV                     = [0|1]
SESH_PRO_BACKEND_WITH_PLATFORM_APPLE     = [0|1]
SESH_PRO_BACKEND_WITH_PLATFORM_GOOGLE    = [0|1]
```

## Build and run

```bash
# Get libsession C++ libraries by setting up the repository with the
# instructions at deb.oxen.io (or install from source
# at https://github.com/session-foundation/libsession-util)
sudo apt install libsession-util-dev

# Install the Python bindings to utilise libsession
git clone https://github.com/oxen-io/libsession-python
cd libsession-python && python -m pip install .

# Install Python dependencies for the Session Pro Backend
python -m pip install -r requirements.txt

# Run backend w/ a local Flask server in debug mode
python -m flask --app main run --debug

# Another example: as above, but on port 8888 with the DB stored in the current
# working directory at ./data/pro.db
SESH_PRO_BACKEND_DB_URL=sqlite:///data/pro.db python -m flask --app main run --debug --port 8888

# Run the tests (with printing test names and test output to stdout enabled)
python -m pytest test.py --verbose --capture=no

# For running in production we use UWSGI which run multiple instances of the
# Flask app with process lifecycle management, the following command is
# suitable.
#
# Note that the following runs it on a local UWSGI server. If you wish to run
# this from behind a reverse proxy, you want to use (--http-socket) instead of
# (--http) to defer the routing of requests to something like Nginx or Caddy.
# See this link for more details:
#
#   https://uwsgi-docs.readthedocs.io/en/latest/WSGIquickstart.html#putting-behind-a-full-webserver
#   https://uwsgi-docs.readthedocs.io/en/latest/HTTP.html
#
# Or alternatively see how oxen-observer in our ecosystem is configured for
# another reasonable real-world example:
#
#   https://github.com/oxen-io/oxen-observer
#
# Run the backend w/ local UWSGI on port 8000 with 4 processes (i.e. 4 HTTP request
# handlers) with the DB stored in the current working directory at ./data/pro.db
#
# Threads must be enabled (--enable-threads) on UWSGI. By default UWSGI does not
# enable the Python GIL so threads generated by the application will never run.
# Our backend spawns one long-running thread for expiring rows in the DB, this
# needs to be running to maintain the integrity of the DB.
#
# Die on terminate (--die-on-term) restores
# UNIX convention in that a SIGTERM should kill the process. UWSGI hijacks this
# and reloads the process. This is the defined behaviour until UWSGI v2.1.
#
# Strict (--strict) and need app (--need-app) abort startup unless all
# configuration options are valid and there's a valid application for UWSGI to
# launch from the process. Any misconfiguration essentially aborts startup.
#
# Vacuum (--vacuum) cleans up any temporary files like sockets that UWSGI
# creates.
#
# Process name prefix (--procname-prefix) assigns a human readable name as the
# process name in the kernel.
SESH_PRO_BACKEND_DB_URL=sqlite:///data/pro.db \
  uwsgi \
  --http 127.0.0.1:8000 \
  --master \
  --wsgi-file main.py \
  --callable flask_app \
  --processes 4 \
  --enable-threads \
  --die-on-term \
  --strict \
  --need-app \
  --vacuum \
  --worker-reload-mercy=5 \
  --procname-prefix \"SESH Pro Backend \"
```

## Command Line Interface

The `cli.py` tool provides a command-line to query and manipulate the database.

```bash
# User error management (requires --config)
python cli.py --config config.ini user-error set "1:token123=true"
python cli.py --config config.ini user-error delete "1:token123"

# Google notification management (requires --config)
python cli.py --config config.ini google-notification handle "12345"
python cli.py --config config.ini google-notification delete "12345"
python cli.py --config config.ini google-notification list

# Revocation management (requires --config)
python cli.py --config config.ini revoke list 0xabcd...
python cli.py --config config.ini revoke delete 0xabcd...
python cli.py --config config.ini revoke timestamp 0xabcd... 1741170600

# Report generation (requires --config)
python cli.py --config config.ini report generate daily --count 7
python cli.py --config config.ini report generate weekly --format csv

# Database inspection (requires --config)
python cli.py --config config.ini db info
python cli.py --config config.ini db print

# Development payment operations (no --config required)
python cli.py dev-payment add --url http://localhost:8000 --provider google --dev-plan 1M
python cli.py dev-payment refund --url http://localhost:8000 --provider google --master-key abcdef... --payment-token tok123 --order-id DEV.abc123
```

Run `python cli.py --help` for full command documentation. Use `--help-full` for detailed
format specifications and examples.

# Deploy Guide

Using `scripts/ansible_deploy.yml` we have an idempotent
script that can set up a primary server to have a Session Pro Backend that is
configured for Google and Apple app stores and persists the state onto
a postgres database. The database is replicated using postgres replication to
the secondary server, details of this are in the `ansible_deploy.yml`
documentation.

The secondary server is optional, opt out by not specifying the `replica_host.`
to the ansible command.

Start by cloning the session-pro-backend at
https://github.com/session-foundation/session-pro-backend.git

Setup a config.ini with the following values and stub lines (the stubs will
be populated by the ansible script and transferred onto the primary server).

```
[base]
db_url                     =
dev                        = true
with_platform_apple        = true
with_platform_google       = true
unsafe_logging             = true
platform_testing_env       = true

[apple]
app_id                     =
bundle_id                  =
issuer_id                  =
key_id                     =
key_path                   =
root_cert_ca_g2_path       =
root_cert_ca_g3_path       =
root_cert_path             =
sandbox_env                =

[google]
cloud_app_credentials_path =
cloud_project_id           =
cloud_subscription_name    =
package_name               =
subscription_product_id    =
```

Then create a hosts.yml file in the working directory with the following
contents. Note for ansible to access the machine ensure that SSH access is setup
from the host to the target servers (primary and secondary).

```yaml
global:
  hosts:
    pro_backend:
      ansible_host: <Primary Instance's IP address>
      ansible_user: root
```

Then attain the Google and Apple secrets (see the `ansible_deploy.yml` file for
where to retrieve/generate these secrets) to enable communications with the
respective platforms:

- Apple Key Path (P8 file)
- Apple Key ID
- Google Cloud App Default Credentials (ADC JSON file)

Additionally you will need various pieces of metadata required for
authenticating to these platforms. See the ansible script for more information
on where to source these from. It's possible to disable these platforms by
simply setting `with_platform_apple` and `with_platform_google` to false. Stub
data can then be supplied to their respective fields.

Then run the ansible command as follows (we assume config.ini and the
secrets are in the current working directory and substituting in the necessary
values, again see `ansible_deploy.yml` for documentation on all these fields and
where to source them):

```bash
ansible-playbook -i hosts.yml playbook_pro_backend_pgsql.yml \
  -e replica_host=<root@secondary_server_address> \
  -e config_ini_path=<path/to/config.ini> \
  \
  -e apple_app_id=<string> \
  -e apple_bundle_id=<string> \
  -e apple_issuer_id=<string> \
  -e apple_key_id=<key_id> \
  -e apple_key_path=<path/to/your_apple_api_key.p8> \
  -e apple_sandbox=false \
  \
  -e google_cloud_app_default_credentials_path=<path/to/your_google_adc_key.json> \
  -e google_cloud_project_id=<string> \
  -e google_cloud_subscription_name=<string> \
  -e google_package_name=<com.your_company.app_name> \
  -e google_subscription_product_id=<string> \
  \
  -e domain=<your.domain.com> \
  -e email=<your@email.com>
```

You will be prompted for a password interactively which is the password to
secure the postgres DB instance under. The password is reused to secure the
secondary's server replicated database.

After the script has ran to completion, the server(s) are now successfully
provisioned and should be accepting requests. On the replica instance you can
run this command to dump the database to stdout to check if the users table was
replicated:

```
sudo -u postgres psql --port={{ pg_port }} -d {{ pg_db_name }} -c "SELECT * FROM users"
```

On the primary instance test one of the unauthenticated endpoints to ensure that
it's visible and accessible publicly:

```
curl -X POST <your_server_address>/get_pro_revocations -H "Content-Type: application/json" -d '{"version": 0, "ticket": 0}'
```
# Architecture

![Overview of Session Pro](docs/Session_Pro_Overview_200_zoom_10_border.png)

Provided in this repository is an [Ansible](scripts/ansible_deploy.yml) script
that installs the Session Pro infrastructure onto the target server and is
a useful, technical description of the various components that the backend
relies on. In general, the backend is designed as a set of distinct layers that
feed data to each other, which is loosely described by the following diagram (in
reality the links between the layers are a bit more entangled but conceptually
stands).

![Code layers of Session Pro](docs/Session_Pro_Code_Layers_200_zoom_10_border.png)

Ultimately the code centralises in on the backend which manages the database and
lifetimes of payments. From here most payment data is processed and upper layers
can request it to produce cryptographic Pro proofs.

## High-level Design

**Session Pro Client Key Derivation**

A Session user’s account has a secret seed `s` from which their current `a/A`
key pair is derived. For Session Pro, [derive a deterministic
key](https://github.com/session-foundation/libsession-util/blob/3033fbc7485a72afb2715931ff5eba324ff64594/src/ed25519.cpp#L112)
we dub the Master Session Pro Key from hashing `s` and generating a new key pair
from that seed.

```
s2  = Blake2b32(s, key="SessionProRandom")
b/B = Ed25519FromSeed(s2)
```

In addition to the master key pair, a secondary transient key pair dubbed the
Rotating Session Pro Key `c/C` is generated that as its name suggests will be
rotated over time.

```
c = Rotating Session Pro Key
```

This key is loosely managed as it can be updated at any point, even during an
active subscription by [registering a new rotating
key](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/server.py#L123)
with a signature from the master key. This key pair (including the secret
component) will be synchronised across clients through
[user config messages](https://github.com/session-foundation/libsession-util/blob/3033fbc7485a72afb2715931ff5eba324ff64594/include/session/config/pro.hpp#L9)
which are stored encrypted on the Session Network swarms.

> This means initially, the client should check if they have a user config
> stored in the swarm first, before generating their own Rotating Session Pro
> key.

The rate at which a Rotating Session Pro key is changed is at the discretion of
the client. Each rotation will require one request to the backend server to
authorise a new certificate to entitle the new Rotating Session Pro key to
Session Pro features.

**Session Pro Backend Server Overview**

The server will initially need to [generate a key
pair](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/backend.py#L717)
for creating cryptographic proofs that entitle a device's rotating key to
Session Pro. It will subscribe to the payment hooks from Google Play, Apple App
Store and in future, third party payment vendors like PayPal, Stripe and BTCPay.
These payment systems in one form or another will [notify the
server](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/backend.py#L1434)
with a confidential payment token upon purchase of a pro subscription to the
backend server as well as to the Session client that initiated the purchase.

**Registering a new pro subscription**

The client will [construct
a request](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/server.py#L25)
after receiving the confidential payment token to the server with a payload
signed by the Master and Rotating Session Pro Key:

- Master Session Pro Public Key
- Rotating Session Pro Public Key
- Blake2b hash of the payment metadata
- Signature for the payload signed by the Master Session Pro public key.
- Signature for the payload signed by the Rotating Session Pro public key.
  (This ensures that the client possesses the corresponding secret for the
  rotating key it wants to authorise).

The server will verify the payload and match the token with the published token
from the payment hook and [create a payment
record](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/backend.py#L1038)
(broadly speaking the main fields are):

- Master Session Pro Public Key
- Subscription duration
- Creation time (rounded up to the next day)
- Activation time (null initially)
- Blake2b hash of confidential payment token

The [user table will be
updated](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/backend.py#L1105)
and track the current generation index allocated to the user and the latest
known subscription expiry date at time of modification.

The generation index is a globally shared monotonic counter across all users
that increments when an event modifies a user’s subscription (extending,
renewal, refunding) that then represents the “last” update to a user’s
subscription status. If the user has a prior generation index assigned, that
[index is
revoked](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/backend.py#L840)
first for the duration of the latest subscription expiry date before being
allocated a new index as well as updating the latest subscription expiry date.

This is necessary because clients are technically allowed to rotate their
Rotating Session Public key as many times as they wish. If not the backend is
forced to remember and revoke every key they have authorised through the
server. The index serves as a way to group all the Rotating Session Public keys
we’ve generated a proof for, under a single identifier such that revocation of
the identifier will revoke all proofs that were generated using it.

> One alternative to the generation index would be using the hash of the
> confidential token to group all the proofs generated for a payment. This works
> but imposes some issues for implementing clients that we can avoid.
>
> From a client’s perspective, the most reasonable approach is to cache a proof
> of their subscription until expiry or revocation. If a subscription is
> extended, clients will have to poll or subscribe to the Session Pro Backend
> server to witness this extension in addition to querying the revocation list.
>
> Another alternative is to limit the number of rotating keys that can be
> registered for a payment token/master key. When the key limit is met, we could
> consider removing keys in a FILO manner, all those keys however have to be
> revoked and so given a motivated enough adversary, the revocation list will
> continue to grow unbounded defeating the whole purpose of trying to bound the
> amount of space a user can occupy in the database.

A proof's expiry is the minimum of either [30 days or the remaining
time](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/backend.py#L1791)
in the subscription [rounded to the end of the
day](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/backend.py#L1111).
This ensures that proofs on the network have a uniform expiration date where
possible to mask the user's subscription plan they are on.

Note that subscription expiry is not the same as proof expiry due to this
clamping and it's very possible that a proof's expiry extends beyond the
subscription expiry. Subscription expiry precisely tracks the entitlement period
that the payment provider is enforcing in order to allow clients to accurately
show the subscription status from the perspective of their payment provider.

This means platform clients should take care to periodically on the ending 24
hours of the subscription to pre-emptively query for a new proof from the
Session Pro Backend to ensure seamless pro entitlement across the expiration
boundary if the user is intending to continue their billing cycle.

In absence of any record with an activation time, we assign the activation time
to the Session Pro Backend Server’s clock for the record with the earliest
creation time. This is important to allow the server to revoke active payment
records whilst continuing to correctly calculate the subsequent expiry dates.

The user table record will consist of:

- Master Session Pro Public Key
- Generation index
- Expiry time
- Proof of pro subscription

Upon successful registration, the server will reply to the client a [proof of
their
subscription](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/server.py#L185):

- Expiry time
- Blake2b hash of (Generation index || Session Pro Backend Server salt)
- Rotating Session Pro Public Key
- Signature for the payload

The generation index is salted to avoid leaking metadata on how early in the
protocol’s lifetime the subscription was modified/active as it starts from 0 and
increments upwards.

**Updating rotating keys**

In the event that a new rotating key is procured by a client (e.g. a key is lost
and a new one is generated), it can be authorised for the subscription by
submitting the ["generate a new
proof"](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/server.py#L123)
request for the backend:

- Master Session Pro Public Key
- Rotating Session Pro Public Key
- Timestamp
- Signature of the payload with the Master Session Pro key
- Signature of the payload with the Rotating Session Pro key

Since the Master Session Pro public key is deterministically derived from the
user's seed, it’s always possible to sign a new request which authorizes a new
rotating key even if said key is lost.

This request will be accepted if the:

- Master Session Pro Public key has any pre-existing payment record
- Timestamp is well within bounds (to prevent replay attacks)

In that case a proof will be replied to the client as per section Proof of pro
subscription.

The generation index remains unchanged which means every additional Rotating
Session Pro Public authored is grouped into the same bucket of proofs for the
current generation. This is useful for when the user’s subscription status is
updated a revocation on that index blocks all the proofs in the same bucket.

Although the rotating keys can be updated at any point, the same key is reused
by syncing it to/from the swarm. Clients on start-up should prioritise keys
found in the user config before determining if they should generate a new
rotating key and/or request to generate a new proof. Clients not doing this
would leak the fact that they have multiple devices with different rotating keys
on the Pro proof.

**Lookup user’s proof of pro subscription**

Since clients will [append the proof of their subscription to their
message](https://github.com/session-foundation/libsession-util/blob/3033fbc7485a72afb2715931ff5eba324ff64594/src/session_protocol.cpp#L503)
there isn’t a need to allow users to lookup from the backend the pro
subscription status of other users. The only way then to ascertain their Pro
status is by messaging the user within a group or 1:1.

If a client itself no longer has possession of their Session Pro proof, it can
re-request it by submitting a request as per Updating rotating keys.

In the event the proof is lost but the Rotating Session Pro key is the same, it
can be resubmitted to get the server to sign a new proof. The server does not
hold onto any rotating keys so it does not care about re-use, just that the user
is in possession of a Master Session Pro public key that has an active
subscription.

**Revoking proofs for refunds**

Once proofs are signed by the Session Pro Backend, they are standalone
certificates, valid to use on the protocol until they expire. When
a subscription is updated/cancelled it is necessary to revoke a certificate
after it has been issued. Since the certificate is valid to use until expiry,
the backend must also maintain an additional [list of
proofs](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/server.py#L195)
that have been revoked. Clients will periodically synchronise this list to
override current
valid proofs.

Upon notification of a refund from the backend’s subscription to the payment
providers, the refund will contain a reference to the confidential payment
token, then:

- The matching payment record will be [marked
  expired](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/backend.py#L857)
- A [revocation record is
  created](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/backend.py#L2100)
  with the fields:
  - Generation index (invalidating all proofs generated under this identifer)
  - Expiry time (which encompasses the total entitlement period of the user)

**Subscription expiry**

On a per-day cycle, the backend will [prune the database of expired
entries](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/backend.py#L2224).
Payments are not pruned yet to allow clients to [lookup their payment
history](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/server.py#L270),
but can be done trivially by checking the expiry timestamp.

**Using proofs on the Session protocol**

The client must be in possession of the specified Rotating Session Pro Public
key in the proof to use it. If the client does not have the key, then it can
restore or procure new keys respectively:

- If the user config message has expired, a new Rotating Session Pro key can be
  generated and authorised as per section Updating rotating keys

- If the user config message is available, then, the key can be restored from
  the user config message.

When submitting a message we append the proof (as per Proof of pro subscription)
as a part of the message payload. A user can be identified as having Session Pro
by verifying the:

- Proof is signed by the Session Pro Backend Server key
- Proof has not expired yet
- Underlying message was signed by the Rotating Session Pro Public key
  referenced in the proof (proving that they know the secret key and are the
  owner of said proof).
- Hash provided in the proof is not on the revocation list

**Metadata**

The following is a summary of inbound and outbound requests for stake holders of
the system: Clients
- Communicate with the backend server using onion requests to mask the IP of the
  client from the server
- Communicate with other clients by appending the proof of pro subscription
  which consists of publicly available data and a masked subscription
  identifier:
    - Version
    - Blake2b hash of (Generation index || Session Pro Backend Server salt)
    - Rotating Session Pro Public Key
    - Subscription expiry date
    - Signature for the payload consisting
- Other clients can link the Session user account to their current rotating key
- Retrieve the revocation list which consists of a list of hashed payment
  identifiers, with no further information derivable from this data.
- Pro subscription registration is sent to and encrypted for the Session Pro
  Backend server.

  The Session Pro backend server can link which payment is for which proof which
  is necessary to be able to revoke or authorise additional keys. It cannot
  reverse the Master Session Pro Public key to the Session user account without
  prior knowledge of the account.

- Communicates with payment providers which allows them to map IP address to
  a confidential payment token

**Server**

Can link a Master Session Pro and Rotation Session Pro key to their payment
token but not the Session user account due to the irreversibility of the Master
Session Pro key to the Session user key.

**Passive Observer**

All client to server communications are done via onion-requests, encrypted and unreadable.
They can collect proofs which consist of only public data and any private data is hashed

- Version
- Blake2b hash of (Generation index || Session Pro Backend Server salt)
- Rotating Session Pro Public Key
- Subscription expiry date
- Signature for the payload

Cannot observe the Master Session Pro public key because it is generated,
blinded with a quasi-random value unknown to an observer without a user’s
Session seed.

**Android Platform**

In-app purchases can be managed through the [REST
interface](https://developers.google.com/android-publisher/api-ref/rest/v3/inappproducts)
or through the [In-app products page in the Play
Console](https://support.google.com/googleplay/android-developer/answer/1153481#zippy=%2Ccreate-a-single-in-app-product)
(also see: [Create and configure your
products](https://developer.android.com/google/play/billing/getting-ready)). To
enable the payments and initiate a purchase through the app, developers will use
the Google Play Billing Library dependency as detailed
[here](https://developer.android.com/google/play/billing/integrate#connect).

After purchase, a [confidential purchase token is
emitted](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/platform_google.py#L450)
to both the Session Pro Backend server and the client. Clients will register by
submitting a request, signed by their Master Session Pro key and desired
Rotating Session Pro key, encrypted for the Session Pro Backend public key. When
a purchase is interrupted, for example, during network instability or crashes,
it’s recommended to call
[BillingClient.queryPurchasesAsync()](https://developer.android.com/google/play/billing/integrate#process)
on start-up to finish any pending processes. Google has a list of recommended
steps to [\*Verify purchases before granting
entitlements](https://developer.android.com/google/play/billing/security#verify).\*

Notifications of purchases are available by ensuring that [Real-time developer
notifications
(RTDN)](https://developer.android.com/google/play/billing/getting-ready#enable-rtdn)
is turned on for one-time products to facilitate our pay-and-extend requirements
for Session Pro. Handling

**Backend support for Android**

Setup the backend to connect to [Google Play’s
publisher](https://developer.android.com/google/play/billing/lifecycle#rtdn-client)
to be notified of actions that change the entitlement of a certain purchase
token (such as purchase or refunds). When notifications are received, Google
Cloud will continue to deliver the notifications until it has been acknowledged.

If the purchase notification is not acknowledged within 3 days of the purchase,
the purchase is [automatically
refunded](https://developer.android.com/google/play/billing/integrate#notifying-google).
The notifications are encoded into the data structures described
[here](https://developer.android.com/google/play/billing/rtdn-reference#encoding).

Google cloud has some fault-tolerance with regards to when the RTDN fails to
publish to the backend, see their [Handling message
failures](https://cloud.google.com/pubsub/docs/handling-failures) section. In
summary

- You can configure the retry policy, immediate or exponential backoff

- Send the failed messages to a dead letter queue

**iOS Platform**

In-app purchases are managed through the [App Store
Connect](https://developer.apple.com/help/app-store-connect/configure-in-app-purchase-settings/overview-for-configuring-in-app-purchases)
which then uses StoreKit to implement the user flow on clients. The
pay-and-extend model falls under the category of *Non-renewing subscriptions*.
Apple coins their notification system the [\*App Store Server
Notifications](https://developer.apple.com/help/app-store-connect/configure-in-app-purchase-settings/enter-server-urls-for-app-store-server-notifications)\*
which we configure our backend server to be a recipient of, about events like
new purchases and refund status.

Enable notifications from the following
[guide](https://developer.apple.com/documentation/appstoreservernotifications/enabling-app-store-server-notifications).
The notifications are encoded in a JSON payload, the decoded payload has the
following
[structure](https://developer.apple.com/documentation/appstoreservernotifications/responding-to-app-store-server-notifications#Recover-from-server-outages).
After purchase a [notification will be
emitted](https://github.com/session-foundation/session-pro-backend/blob/dd6702cdfb47f1beb4f665a8540418c6c5a35e60/platform_apple.py#L320)
to both the client and the Session Pro backend server and a similar user flow to
the Android platform will proceed with registering the user’s subscription.

**Backend support for iOS**

The backend will be configured as the recipient to the App Store Server
Notifications and handle responses as per their
[guide](https://developer.apple.com/documentation/appstoreservernotifications/responding-to-app-store-server-notifications).
Of note for fault-tolerance:

- For version 2 notifications, it retries five times, at 1, 12, 24, 48, and 72
  hours after the previous attempt.

- For version 1 notifications, it retries three times, at 6, 24, and 48 hours
  after the previous attempt.

- Additionally, unlike Google, Apple does have an API to retrieve previous
  purchases if the backend fails to witness them in the [Recover from server
  outages](https://developer.apple.com/documentation/appstoreservernotifications/responding-to-app-store-server-notifications#Recover-from-server-outages)
  section.
