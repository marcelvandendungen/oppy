import jwt
import logging
import os
import sys

from oidcpy import authorize, AuthorizeError

from flask import Flask, request, make_response, jsonify


def init_logging(name):
    ""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    return logger


logger = init_logging(__name__)
app = Flask(__name__)
app.config['TESTING'] = os.environ.get('TESTING') == 'True'


@app.errorhandler(Exception)
def error_handler(ex):
    if isinstance(ex, (jwt.ExpiredSignatureError, jwt.DecodeError, AuthorizeError)):
        logger.error(str(ex))
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
