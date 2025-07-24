# Session Pro Backend

A server powered by Python, Flask and uWSGI to manage the lifetime of a Session
Pro subscription for Session users such as:

- Registering payments for Session Pro subscriptions
- Producing crytographic proofs to entitle cryptographic keys to use Session Pro
  features on the Session protocol
- Pruning expired and revoke cryptographic proofs
- Authorising new cryptographic keys for a pre-existing subscription

And so forth.

# Getting started

## Options

Set the following environment variables to customise the behaviour of the
backend:

```
# Set the location to store the database of the backend to
SESH_PRO_BACKEND_DB_PATH=<path/to/db>.db (default: ./backend.db)

# Pretty print the contents of the tables in the database to standard out and
# exit
SESH_PRO_BACKEND_PRINT_TABLES=[0|1] (default: ./backend.db)
```

## Build and run

```bash
# Install dependencies
python -m pip install -r requirements.txt

# Run backend w/ a local Flask server in debug mode
python -m flask --app main run --debug

# Another example: as above, but on port 8888 with the DB stored in the current
# working directory at ./data/pro.db
SESH_PRO_BACKEND_DB_PATH=./data/pro.db python -m flask --app main run --debug --port 8888

# Run the tests
python -m pytest test.py
```
