from flask import make_response, render_template


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
        # validate required request parameters
        self.client_id = self.validate_has_parameter('client_id', 400)
        self.response_type = self.validate_has_parameter('response_type', 302)

    @classmethod
    def from_request_parameters(cls, parameters):
        return AuthorizeRequest(parameters)

    @classmethod
    def from_form_variables(cls, variables):
        return AuthorizeRequest(variables)

    def process(self, clients):
        "Handles initial redirect to OP, validates query parameter and displays login page"

        # client id must identify a registered client
        client = next((item for item in clients if item['client_id'] == self.client_id), None)
        if not client:
            raise AuthorizeRequestError(400, 'unknown_client', 'Client not registered')

        # only support code flow for now
        if self.parameters['response_type'] != 'code':
            raise AuthorizeRequestError(302, 'unsupported_response_type', 'unsupported flow')

        # redirect_uri query parameter is optional, but when specified must match one of the registed URIs
        if 'redirect_uri' in self.parameters and self.parameters['redirect_uri'] not in client['redirect_uris']:
            raise AuthorizeRequestError(400, 'invalid_redirect_uri', 'Not a registerd redirect uri')

        # require PKCE for public clients
        if client['public']:
            self.code_challenge = self.validate_has_parameter('code_challenge', 302)
            self.code_challenge_method = self.validate_has_parameter('code_challenge_method', 302)
            if self.code_challenge_method != "SHA256":
                raise AuthorizeRequestError(302, 'invalid_request', 'Invalid code challenge method')

        return self.parameters

    def issue_code(self):
        "Handles the credential verification and issues the authorization code"
        return "authorize endpoint"

    def validate_has_parameter(self, parameter, error_code):
        if parameter not in self.parameters:
            raise AuthorizeRequestError(error_code, 'invalid_request', parameter + ' parameter is missing')
        return self.parameters[parameter]
