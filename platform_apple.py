import flask

ROUTE_NOTIFICATIONS_APPLE_APP_CONNECT_SANDBOX = '/notifications_v2_apple_app_connect_sandbox'

flask_blueprint = flask.Blueprint('session-pro-backend-notifications-apple-app-connect', __name__)

@flask_blueprint.route(ROUTE_NOTIFICATIONS_APPLE_APP_CONNECT_SANDBOX, methods=['POST'])
def notifications_apple_app_connect_sandbox() -> flask.Response:
    print(f"Request: {flask.request.data}")
    flask.abort(500)
