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

```ini
[base]
# Set the location to store the database of the backend to
db_path                      = <path/to/db>

# If you wish to use an in-memory database or shared in-memory database (i.e.
# 'file::memory') this flag must be set. See:
#
#   https://www.sqlite.org/inmemorydb.html
db_path_is_uri               = false

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
SESH_PRO_BACKEND_DB_PATH              = [0|1]
SESH_PRO_BACKEND_DB_PATH_IS_URI       = [0|1]
SESH_PRO_BACKEND_PRINT_TABLES         = [0|1]
SESH_PRO_BACKEND_DEV                  = [0|1]
SESH_PRO_BACKEND_WITH_PLATFORM_APPLE  = [0|1]
SESH_PRO_BACKEND_WITH_PLATFORM_GOOGLE = [0|1]
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
# Lazy apps `--lazy-apps` ensures that each spawned process runs our
# `entry_point` in main # instead of having 1 master process that runs it and
# then multiple sub-workers that sit-idle waiting for requests via flask. This
# is required as otherwise UWSGI has problems terminating the workers (for some
# reason, see: https://github.com/unbit/uwsgi/issues/1609). Ordinarily you would
# want to use `py-call-osafterfork` however that option is not supported on some
# older versions of UWSGI still in-use.

# (It may be possible to replace this with the injected uwsgi.signals Python
# module by UWSGI when it launches the backend. However that leaks UWSGI
# implementation detail into the backend and also it's a good idea that child
# processes follow UNIX conventions as you'd expect them to in the first place).
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
  --lazy-apps \
  --procname-prefix \"SESH Pro Backend \"
```
