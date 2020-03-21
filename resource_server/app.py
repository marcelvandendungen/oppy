import jwt
import os
import sys

from resource_server.authorize import authorize, AuthorizeError

from flask import Flask, request


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
        return str(claims)
    except KeyError as ex:
        return str(ex)


def main():
    print('running resource server')
    app.run(host='0.0.0.0', port=5001, debug=app.config['TESTING'])


if __name__ == "__main__":
    sys.exit(main())
