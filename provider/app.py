import jwt
import os
import sys

from flask import Flask
from provider.endpoints.authorize.authorize import create_blueprint as create_authorize_blueprint
from provider.endpoints.token.token import create_blueprint as create_token_blueprint
from provider.endpoints.register.register import create_blueprint as create_register_blueprint
from provider.endpoints.jwk.jwk import create_blueprint as create_jwk_blueprint
from provider.endpoints.metadata.metadata import create_blueprint as create_metadata_blueprint
from provider.endpoints.consent.consent import create_blueprint as create_consent_blueprint
from provider.endpoints.scim.scim import create_blueprint as create_scim_blueprint
from provider.endpoints.userinfo.userinfo import create_blueprint as create_userinfo_blueprint
from provider.endpoints.logout.logout import create_blueprint as create_logout_blueprint
from provider.model.store.client_store import client_store
from provider.util import init_config, init_logging
from oidcpy.authorize import AuthorizeError
from oidcpy.crypto import read_keys


config_path = 'provider/config.yml'

config = init_config(config_path)
logger = init_logging(__name__)

keypair = read_keys("./provider/private.pem", "./provider/public.pem")
app = Flask(__name__, static_url_path='')
# app.config['EXPLAIN_TEMPLATE_LOADING'] = True
app.config['TESTING'] = os.environ.get('TESTING') == 'True'
app.register_blueprint(create_authorize_blueprint(client_store, keypair.public, keypair.private))
app.register_blueprint(create_token_blueprint(client_store, keypair.private, config))
app.register_blueprint(create_register_blueprint(client_store))
app.register_blueprint(create_jwk_blueprint())
app.register_blueprint(create_metadata_blueprint(config))
app.register_blueprint(create_consent_blueprint(config))
app.register_blueprint(create_scim_blueprint(config))
app.register_blueprint(create_userinfo_blueprint(config))
app.register_blueprint(create_logout_blueprint(config, keypair.public))


@app.errorhandler(Exception)
def error_handler(ex):
    logger.error(f'exception type: {type(ex)}')
    logger.exception(ex)
    if isinstance(ex, (jwt.ExpiredSignatureError, jwt.DecodeError, AuthorizeError)):
        return str(ex), 401
    return str(ex), 500


def main():
    app.run(host='0.0.0.0', port=5000, debug=app.config['TESTING'],
            ssl_context=('provider/cert.pem', 'provider/key.pem'))


if __name__ == "__main__":
    sys.exit(main())
