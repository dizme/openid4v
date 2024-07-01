from idpyoidc.server.oidc.userinfo import UserInfo
from cryptojwt.jwt import utc_time_sans_frac
from datetime import datetime
import logging
from flask import make_response

logger = logging.getLogger(__name__)


class Deferred_Credential(UserInfo):
    endpoint_name = "deferred_credential_endpoint"
    name = "deferred_credential"

    def __init__(self, upstream_get, conf=None, **kwargs):
        UserInfo.__init__(self, upstream_get, conf=conf, **kwargs)

    def verify_token_and_authentication(self, request):
        _mngr = self.upstream_get("context").session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(
                request["access_token"], grant=True, handler_key="access_token"
            )
        except (KeyError, ValueError):
            return self.error_cls(
                error="invalid_token", error_description="Invalid Token"
            )

        _grant = _session_info["grant"]
        token = _grant.get_token(request["access_token"])
        # should be an access token
        if token and token.token_class != "access_token":
            return self.error_cls(
                error="invalid_token", error_description="Wrong type of token"
            )

        # And it should be valid
        if token.is_active() is False:
            return self.error_cls(
                error="invalid_token", error_description="Invalid Token"
            )

        _auth_event = _grant.authentication_event
        # if the authentication is still active or offline_access is granted.
        if not _auth_event["valid_until"] >= utc_time_sans_frac():
            logger.debug(
                "authentication not valid: {} > {}".format(
                    datetime.fromtimestamp(_auth_event["valid_until"]),
                    datetime.fromtimestamp(utc_time_sans_frac()),
                )
            )
            return False, None

            # This has to be made more finegrained.
            # if "offline_access" in session["authn_req"]["scope"]:
            #     pass
        return True, _session_info["client_id"]

    def process_request(self, request=None, **kwargs):
        if "transaction_id" not in request:
            return self.error_cls(error="invalid_notification_id")

        transaction_id = request["transaction_id"]

        tokenAuthResult = self.verify_token_and_authentication(request)
        if "error" in tokenAuthResult:
            return tokenAuthResult

        allowed, client_id = tokenAuthResult
        if not isinstance(allowed, bool):
            return allowed

        if not allowed:
            return self.error_cls(
                error="invalid_token", error_description="Access not granted"
            )

        try:
            _mngr = self.upstream_get("context").session_manager
            _session_info = _mngr.get_session_info_by_token(
                request["access_token"], grant=True, handler_key="access_token"
            )
        except (KeyError, ValueError):
            return self.error_cls(
                error="invalid_token", error_description="Invalid Token"
            )

        if transaction_id not in _session_info["grant"].transaction_ids:
            _resp = {
                "error": "invalid_transaction_id",
            }
            return {"response_args": _resp, "client_id": client_id}

        if _session_info["grant"].transaction_ids[transaction_id]:
            _resp = _session_info["grant"].transaction_ids[transaction_id]

            _session_info["grant"].transaction_ids.pop(transaction_id)
        else:
            _resp = {"error": "issuance_pending", "interval": 30}
            return {"response_args": _resp, "client_id": client_id}

        return {"response_args": _resp, "client_id": client_id}

        # return make_response("", 204)
