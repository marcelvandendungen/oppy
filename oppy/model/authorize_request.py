from flask import make_response, render_template
from urllib.parse import urlencode


class AuthorizeRequestError(RuntimeError):
    def __init__(self, http_code, error, error_description, error_uri=""):
        self.http_code = http_code
        self.error = error
        self.error_description = error_description
        self.error_uri = error_uri

class AuthorizeRequest:
    "Class to handle the OIDC code flow authorization request"

    def __init__(self, dictionary):
        self.parameters = dictionary

    @classmethod
    def from_request_parameters(cls, parameters):
        cls.validate_has_parameter(parameters, 'client_id', 400)
        cls.validate_has_parameter(parameters, 'response_type', 302)
        return AuthorizeRequest(parameters)

    @classmethod
    def from_form_variables(cls, variables):
        cls.validate_has_parameter(variables, 'client_id', 400)
        return AuthorizeRequest(variables)

    def process(self, clients):
        "Handles initial redirect to OP, validates query parameter and displays login page"

        # client id must identify a registered client
        client = next((item for item in clients if item['client_id'] == self.parameters['client_id']), None)
        if not client:
            raise AuthorizeRequestError(400, 'unknown_client', 'Client not registered')

        # only support code flow for now
        if self.parameters['response_type'] != 'code':
            raise AuthorizeRequestError(302, 'unsupported_response_type', 'unsupported flow')

        # redirect_uri query parameter is optional, but when specified must match one of the registed URIs
        if 'redirect_uri' in self.parameters and self.parameters['redirect_uri'] not in client['redirect_uris']:
            raise AuthorizeRequestError(400, 'invalid_redirect_uri', 'Not a registered redirect uri')

        # require PKCE for public clients
        if client['public']:
            self.code_challenge = self.validate_has_parameter(self.parameters, 'code_challenge', 302, 'code challenge required')
            self.code_challenge_method = self.validate_has_parameter('code_challenge_method', 302)
            if self.code_challenge_method != "SHA256":
                raise AuthorizeRequestError(302, 'invalid_request', 'Invalid code challenge method')

        # only support code flow for now
        if self.parameters.get('scope'):
            self.scope = self.parameters['scope']

        return self.parameters

    def redirection_url(self, clients):
        "Handles the credential verification and issues the authorization code"

        # throw Error if username or password missing
        self.validate_has_parameter(self.parameters, 'username', 400, 'username not found')
        self.validate_has_parameter(self.parameters, 'password', 400, 'password not found')

        # client id must identify a registered client
        client = next((item for item in clients if item['client_id'] == self.parameters['client_id']), None)
        if not client:
            raise AuthorizeRequestError(400, 'unknown_client', 'Client not registered')

        # redirect to redirect_uri with code and state as query parameters
        query_params = {
            'code': self.issue_code()
        }

        if self.parameters.get('state'):
            query_params['state'] = self.parameters['state']

        return client['redirect_uris'][0] + '?' + urlencode(query_params)

    def issue_code(self):
        return 'abcdef' # TODO: issue real code

    @staticmethod
    def validate_has_parameter(parameters, parameter, error_code, error_description=""):
        if parameter not in parameters:
            description = parameter + ' parameter is missing' if error_description == "" else error_description
            raise AuthorizeRequestError(error_code, 'invalid_request', description)
        return parameters[parameter]
