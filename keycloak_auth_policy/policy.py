import logging
import warnings

from keycloak.exceptions import KeycloakError
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Everyone, Authenticated
from zope.interface import implementer

LOG = logging.getLogger(__name__)


@implementer(IAuthenticationPolicy)
class KeycloakBasedAuthenticationPolicy:
    """
    Authentication policy which uses a Keycloak's OpenID API via a client
    to authenticate the user. It uses cookies to hold the access token and
    the refresh token.
    """

    def __init__(self, openid_client,
                 access_token_cookie_name="act",
                 refresh_token_cookie_name="rft"):
        """
        :param openid_client: the openid client
        :type openid_client: keycloak.KeycloakOpenID
        :param access_token_cookie_name: the name of the access token cookie
        :type access_token_cookie_name: str
        :param refresh_token_cookie_name: the name of the refresh token cookie
        :type refresh_token_cookie_name: str
        """

        self._openid_client = openid_client
        self.access_token_cookie_name = access_token_cookie_name
        self.refresh_token_cookie_name = refresh_token_cookie_name

    def authenticated_userid(self, request):
        """
        Validates the JWT token and returns the user principal.
        Tries to refresh it before if the token is not valid anymore.

        :param request: the pyramid request
        :type request: pyramid.request.Request
        :return: a dictionary with the user's principals
        :rtype: dict or None
        """
        access_token, refresh_token = request.unauthenticated_userid

        # if there is no access token, we return with None
        if not access_token:
            return None

        principal = self._introspect(access_token)

        if not self._active_principal(principal):
            # if we couldn't retrieve a principal and there's no refresh token
            # we return with None
            if not refresh_token:
                return None

            try:
                token_response = self._openid_client.refresh_token(
                    refresh_token)
            except KeycloakError as e:
                LOG.debug("could not refresh the token: {}"
                          .format(str(e)))
                return None

            access_token = token_response.get("access_token")
            request.response.set_cookie(
                self.access_token_cookie_name, access_token)

            refresh_token = token_response.get("refresh_token")
            request.response.set_cookie(
                self.refresh_token_cookie_name, refresh_token)

            principal = self._introspect(access_token)
            if not self._active_principal(principal):
                return None

        return principal

    def unauthenticated_userid(self, request):
        """
        Gets the access token and refresh token from the cookies.

        :param request: the pyramid request
        :type request: pyramid.request.Request
        :return: a tuple of the access token and the refresh token, where both
        can be None
        :rtype: tuple[str or None,str or None]
        """
        access_token = request.cookies.get(self.access_token_cookie_name)
        refresh_token = request.cookies.get(self.refresh_token_cookie_name)

        return access_token, refresh_token

    def effective_principals(self, request):
        """
        Returns a list of effective principals for this request for
        the given user.

        :param request: the pyramid request
        :type request: pyramid.request.Request
        :return: a list of the effective principals for the user
        :rtype: list of str
        """
        principals = [Everyone]
        user_principal = request.authenticated_userid

        if user_principal:
            roles = user_principal.get('realm_access', {}).get('roles', [])
            principals.append(Authenticated)
            for role in roles:
                principals.append(role)

        return principals

    def remember(self, request, userid, **kw):
        warnings.warn("Session is managed by Keycloak itself. Using remember()"
                      " has no effect.", stacklevel=3)
        return []

    def forget(self, request):
        """
        Removes the user session in keycloak and deletes the cookies from
        the client.

        :param request: the pyramid request
        :type request: pyramid.request.Request
        :return: a sequence of header tuples suitable for forgetting
        the tokens stored in the cookies
        :rtype: list[tuple[str,str]]
        """
        refresh_token = request.cookies.get(self.refresh_token_cookie_name)

        try:
            self._openid_client.logout(refresh_token)
        except KeycloakError as e:
            LOG.debug("could not log out from keycloak: {}".format(str(e)))

        return [("Set-Cookie",
                 "{cookie_name}=; path=/; "
                 "expires=Thu, 01 Jan 1970 00:00:00 GMT"
                 .format(cookie_name=self.access_token_cookie_name)),
                ("Set-Cookie",
                 "{cookie_name}=; path=/; "
                 "expires=Thu, 01 Jan 1970 00:00:00 GMT"
                 .format(cookie_name=self.refresh_token_cookie_name))]

    def _introspect(self, access_token):
        """
        Introspects the access token via the openid client.

        :param access_token: the access token
        :type access_token: str
        :return: the user principal or None if we could not introspect the
        token
        :rtype: dict or None
        """
        principal = None
        try:
            principal = self._openid_client.introspect(access_token)
        except KeycloakError as e:
            LOG.debug("could not introspect token: {}".format(str(e)))

        return principal

    def _active_principal(self, principal):
        """
        Checks whether the principal is active.

        :param principal: the principal to check
        :type principal: dict or None
        :return: whether the principal is active
        :rtype: bool
        """
        return principal and principal.get("active") is True
