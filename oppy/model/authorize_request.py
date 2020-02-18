from flask import make_response, render_template


class AuthorizeRequestError(RuntimeError):
    def __init__(self, error_code, error_message):
        self.error_code = error_code
        self.error_message = error_message

class AuthorizeRequest:
    "Class to handle the OIDC code flow authorization request"

    def __init__(self, dictionary):
        self.parameters = dictionary
        # validate request parameters
        self.client_id = self.validate_has_parameter('client_id', 400)
        self.redirect_uri = self.validate_has_parameter('redirect_uri', 400)
        self.response_type = self.validate_has_parameter('response_type', 302)

    @classmethod
    def from_request_parameters(cls, parameters):
        return AuthorizeRequest(parameters)

    @classmethod
    def from_form_variables(cls, variables):
        return AuthorizeRequest(variables)

    def process(self, clients):
        "Handles initial redirect to OP, validates query parameter and displays login page"

        client = next((item for item in clients if item['client_id'] == self.client_id), None)
        if not client:
            raise AuthorizeRequestError(400, 'unknown client')

        if self.parameters['response_type'] != 'code':
            raise AuthorizeRequestError(302, 'unsupported flow')

        if self.parameters['redirect_uri'] != client['redirect_uri']:
            raise AuthorizeRequestError(400, 'invalid redirect uri')

        return self.parameters

    def issue_code(self):
        "Handles the credential verification and issues the authorization code"
        return "authorize endpoint"

    def validate_has_parameter(self, parameter, error_code):
        if parameter not in self.parameters:
            raise AuthorizeRequestError(error_code, parameter + ' parameter is missing')
        return self.parameters[parameter]
