from os import environ as env
from flask import Flask, jsonify, Response
from flask_cors import cross_origin
from AuthHelper import requires_auth, requires_scope
from AuthError import AuthError

APP = Flask(__name__)


# Controllers API
@APP.route("/api/public")
@cross_origin(headers=["Content-Type", "Authorization"])
def public():
    """No access token required to access this route
    """
    response = "Hello from a public endpoint! You don't need to be authenticated to see this."
    return jsonify(message=response)


@APP.route("/api/private")
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://localhost:3000"])
@requires_auth
def private():
    """A valid access token is required to access this route
    """
    response = "Hello from a private endpoint! This is post validation"
    return jsonify(message=response)

@APP.route("/api/private-scoped")
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://localhost:3000"])
@requires_auth
def private_scoped():
    """A valid access token and an appropriate scope are required to access this route
    """
    if requires_scope("read:messages"):
        response = "Hello from a private endpoint! You need to be authenticated and have a scope of read:messages to see this."
        return jsonify(message=response)
    raise AuthError({
        "code": "Unauthorized",
        "description": "You don't have access to this resource"
    }, 403)

@APP.errorhandler(AuthError)
def handle_auth_error(ex: AuthError) -> Response:
    """
    serializes the given AuthError as json and sets the response status code accordingly.
    :param ex: an auth error
    :return: json serialized ex response
    """
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=env.get("PORT", 3010))
