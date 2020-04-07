import jwt
import os
import sys

from resource_server.authorize import authorize, AuthorizeError

from flask import Flask, request, make_response, jsonify


app = Flask(__name__)
app.config['TESTING'] = os.environ.get('TESTING') == 'True'


@app.errorhandler(Exception)
def error_handler(ex):
    if isinstance(ex, (jwt.ExpiredSignatureError, jwt.DecodeError, AuthorizeError)):
        return str(ex), 401
    return str(ex), 500


app.config['TRAP_HTTP_EXCEPTIONS'] = True
app.register_error_handler(Exception, error_handler)


@app.route('/resource')
@authorize(audience='urn:my_service', scopes='read')    # must be innermost decorator
def resource():
    try:
        claims = request.view_args['claims']
        resp = make_response(jsonify(claims))
        resp.headers['Content-Type'] = 'application/json'
        return resp, 200
    except KeyError as ex:
        return str(ex)


def main():
    app.run(host='0.0.0.0', port=5002, debug=app.config['TESTING'],
            ssl_context=('cert.pem', 'key.pem'))


if __name__ == "__main__":
    sys.exit(main())
