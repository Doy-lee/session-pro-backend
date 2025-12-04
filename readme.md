# Session Pro Backend

A server powered by Python3 and Flask to manage the lifetime of a Session
Pro subscription for Session users such as:

- Registering payments for Session Pro subscriptions
- Producing crytographic proofs to entitle cryptographic keys to use Session Pro
  features on the Session protocol
- Pruning expired and revoke cryptographic proofs
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

- `platform_apple.py`: iOS App Store layer that exposes a HTTP route to receive
  subscription purchases and convert it into a Session Pro Proof.

- `platform_google*.py`: Google Play Store layer that subscribes to Google
services to witness subscription purchases and convert it into a Session Pro
Proof.

- `server.py`: HTTP layer that parses client requests and forwards them to backend
layer and replies a response, if any.

- `test.py`: Holds the unit tests implemented via pytest.

# Getting started

## Options

Customise the runtime behaviour of the server by specifying a .INI file via the environment variable
`SESH_PRO_BACKEND_DB_PATH=<path/to/ini/file.ini>` (due to some UWSGI restrictions).

Note Python's implementation does not use quotes fro strings.

```ini
[base]
# Set the location to store the database of the backend to
db_path                      = <path/to/db>

# If you wish to use an in-memory database or shared in-memory database (i.e.
# 'file::memory') this flag must be set. See:
#
#   https://www.sqlite.org/inmemorydb.html
db_path_is_uri               = false

# Set the path where logs and rotated logs will be stored (keep this line empty to use the default
# and store logs in the executable directory)
log_path                     = <path/to/log>

# Pretty print the contents of the tables in the database to standard out and exit
print_tables                 = false

# Start the server in developer mode, this is most likely only interesting if
# you are developing locally. If the the DB hasn't been bootstrapped yet, this
# causes the backend to generate a deterministic secret Ed25519 key with 32 0xCD
# bytes and hence creates the following key pairs:
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
# payments that have a modified duration (e.g. Google modifies 1 day subscription to be 10s). This
# will modify some functionality with event timestamps to ensure that these timespans are respected
#
# One example is rounding timestamps to Google/Apple's modified timespan to determine whether or not
# a revocation overlaps with the expiry of a payment. If there's an overlap the backend can skip
# issuing a revocation (which is an expensive operation).
platform_testing_environment = false

# By default the backend is configured to strip personal-identifying information (PII) from the
# logs. Enabling this preserves all information in those logs. This should not be used in a
# production use-case.
unsafe_logging               = false

# A ',' delimited string to instruct the DB to delete the specified rows from the user errors table
# in the DB on startup. This value must be of the format
#
#   "<payment_provider integer>:<payment_id>=[true|false], ..."
#
# For example
#
#   "1:the_google_order_id=true,2:the_apple_order_id=false"
#
# Which will add the row that has a payment provider of 1 (which corresponds to the Google Play
# Store) and has a payment ID that matches "google_order_id" to have an error. For the next entry
# similarly it will set the Apple row to false (e.g. delete the row from the DB)
#
# Keep this as an empty string to opt out this functionality. This is intended to be used to flush
# errors from the DB if they are encountered during the handling of payment notifications for a
# specific user. Platform clients may be using the error table to populate UI that indicates that a
# user should contact support, hence clearing this value may clear the error prompt for said user.
set_user_errors              =

# A ',' delimited string to instruct the DB to mark the specified rows as handled or delete the rows
# from the google notification history table in the DB on startup. This value must be of the format
#
#   "<message_id>=[handled|deleted], ..."
#
# For example
#
#   "12345=deleted,8392=handled"
#
# Which will delete the row with a message ID of 12345 and mark the row with the message ID of 8392
# to being handled (which stops the backend from trying to process the message). Note that when you
# handle a message, this also wipes the notification payload from the table (since the backend does
# not need to parse and process the message anymore).
#
# Handled notifications will get deleted at the expiry date and persist in the database just incase
# Google redelivers the notification. Duplicated notifiations are de-duped by their message ID.
#
# Similarly, keep this as an empty string to opt out. This is intended to flush out bad
# notifications that may be invalid or no longer necessary to process/impossible to process due to
# inconsistent DB state, otherwise, do not use unless you know the intended consequences! Make a
# backup of the DB before proceeding!
set_google_notification      = <command...>

session_webhook_url          = <url...>

# Set the URL to the Session Webhook Manage URL to push warning and error logs to at runtime. Each
# subsequent webhook should be in a section with consecutive, incrementing indexes. Omit this
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

# This is required if running in production mode (e.g. `sandbox_env` is false) otherwise we are
# unable to startup Apple's library
production_app_id            = <int: app_id>

# NOTE: The [google] section and its fields are only required if `with_platform_google` is defined
[google]
package_name                 = <string: package_name> # e.g. com.company.my_application
project_name                 = <string: project_name> # e.g. company-ABCDE

# Name of the Google cloud subscription to listen to
subscription_name            = session-pro-sub

# Name of the product to handle Google Play notifications from
subscription_product_id      = session_pro

# Google application credentials .JSON file
application_credentials_path = <path/to/credentials>.json
```

A subset of the options specifiable by the .INI file can be overridden using
environment variables with the exception of `SESH_PRO_BACKEND_INI_PATH` which
can only be specified as an environment variable.

```
# Path to load the .INI file and hence the options to customise the runtime behaviour
SESH_PRO_BACKEND_INI_PATH=<path/to/ini/file.ini>

# For the following options, see the .INI section for more information
SESH_PRO_BACKEND_DB_PATH                 = <...>
SESH_PRO_BACKEND_DB_PATH_IS_URI          = [0|1]
SESH_PRO_BACKEND_LOG_PATH                = <...>
SESH_PRO_BACKEND_PRINT_TABLES            = [0|1]
SESH_PRO_BACKEND_DEV                     = [0|1]
SESH_PRO_BACKEND_WITH_PLATFORM_APPLE     = [0|1]
SESH_PRO_BACKEND_WITH_PLATFORM_GOOGLE    = [0|1]
SESH_PRO_BACKEND_SET_USER_ERRORS         = <...>
SESH_PRO_BACKEND_SET_GOOGLE_NOTIFICATION = <...>
SESH_PRO_BACKEND_SESSION_WEBHOOK_URL     = https://...
SESH_PRO_BACKEND_SESSION_WEBHOOK_NAME    = <...>
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
SESH_PRO_BACKEND_DB_PATH=./data/pro.db python -m flask --app main run --debug --port 8888

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
# `py-call-osafterfork` should be enabled if your UWSGI installation supports it
# which lets the backend attach to the signal handler and gracefully terminate
# the thread that the backend spawns. If your UWSGI version does not support
# this the best we can do is instead `--worker-reload-mercy=3` which causes
# UWSGI to forcibly terminate the thread after 3 seconds, configure the timeout
# as necessary. Without this, on exit the application hangs.
#
# Die on terminate (--die-on-term) similar to `py-call-osafterfork` restores
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
SESH_PRO_BACKEND_DB_PATH=./data/pro.db \
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
  --py-call-osafterfork \
  --worker-reload-mercy=3 \
  --procname-prefix \"SESH Pro Backend \"
```
