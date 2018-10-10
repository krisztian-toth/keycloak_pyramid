# Keycloak based authentication policy for Pyramid framework


Authentication policy which uses Keycloak's OpenID API via a client
to authenticate the user. It uses cookies to hold the access token and
the refresh token.

This package is dependant on the package `python-keycloak`.

## Usage

```python
from keycloak import KeycloakOpenID
from pyramid.config import Configurator
from keycloak_auth_policy import KeycloakBasedAuthenticationPolicy

def main():
    openid_client = KeycloakOpenID(...)
    config = Configurator()
    config.set_authentication_policy(
        KeycloakBasedAuthenticationPolicy(openid_client))
```

You have to handle the redirect logic in your forbidden view based on your 
needs:

```python
from pyramid.httpexceptions import HTTPFound, HTTPForbidden
from pyramid.request import Request
from pyramid.view import forbidden_view_config

@forbidden_view_config()
def forbidden_view(request: Request):
    if ...: # user has no privileges
        raise HTTPForbidden("You don't have permissions for this action")

    # Keycloak's URL to redirect to where the user can log in
    url = ...

    # you can either redirect to the URL or return it if you have a client 
    # which consumes your API
    return HTTPFound(url)
``` 

You also need to have a callback endpoint where Keycloak redirects to after a 
successful login

```python
from keycloak.exceptions import KeycloakError
from pyramid.httpexceptions import HTTPFound
from pyramid.request import Request
from pyramid.view import view_defaults, view_config


@view_defaults(renderer='json')
class AuthApi:

    def __init__(self, request: Request) -> None:
        self.request = request
        self._openid_client = ... # get OpenID client

    @view_config(route_name='auth.exchange', request_method='GET',
                 permission='public')
    def exchange(self):
        try:
            token_response = self._openid_client.exchange(
                self.request.GET.get("code"),
                self.request.route_url("auth.exchange")) # the redirect URI
        except KeycloakError as e:
            ... # handle exception

        access_token = token_response.get("access_token")
        refresh_token = token_response.get("refresh_token")

        # set the tokens as cookies to the client and return a response
        # you can either redirect from here or if your application is consumed
        # as an API you can return a successful response
        response = HTTPFound(...)
        response.set_cookie("refresh_token_cookie_name", refresh_token)
        response.set_cookie("access_token_cookie_name", access_token)

        return response
```

You can also implement a logout endpoint if you feel like to

```python
from pyramid.security import forget

    ...
    
    @view_config(route_name='auth.logout', request_method='GET',
                 permission='private')
    def logout(self):
        headers = forget(self.request)
        response = self.request.response
        response.headerlist.extend(headers)
        return response
```

For more information see the docstrings of each method in the source.