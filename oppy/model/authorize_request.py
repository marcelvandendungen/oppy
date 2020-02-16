
class AuthorizeRequest:
    "Class to handle the OIDC code flow authorization request"
    
    def process(self, args):
        "Handles initial redirect to OP, validates query parameter and displays login page"
        return "authorize endpoint"

    def issue(self, vars):
        "Handles the credential verification and issues the authorization code"
        return "authorize endpoint"
