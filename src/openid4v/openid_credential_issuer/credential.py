import logging
from typing import Optional
from typing import Union
from datetime import datetime

from cryptojwt.jws.jws import factory
from cryptojwt.jwt import utc_time_sans_frac
import requests
from fedservice.entity.utils import get_federation_entity
from idpyoidc.exception import RequestError
from idpyoidc.message import Message
from idpyoidc.message import oidc
from idpyoidc.server import Endpoint
from idpyoidc.server.util import execute
from idpyoidc.util import rndstr
from idpysdjwt.issuer import Issuer

from openid4v.message import CredentialDefinition
from openid4v.message import CredentialRequest
from openid4v.message import CredentialResponse

import json
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64
import cbor2
from pycose.messages import Sign1Message
from pycose.keys import CoseKey


logger = logging.getLogger(__name__)


def get_keyjar(unit):
    _fed = get_federation_entity(unit)
    if _fed:
        return _fed.keyjar
    else:
        return unit.upstream_get("attribute", "keyjar")


class CredentialConstructor(object):

    def __init__(self, upstream_get, **kwargs):
        self.upstream_get = upstream_get

    def calculate_attribute_disclosure(self, info):
        attribute_disclosure = self.upstream_get("context").claims.get_preference(
            "attribute_disclosure"
        )
        if attribute_disclosure:
            return {
                "": {k: v for k, v in info.items() if k in attribute_disclosure[""]}
            }
        else:
            return {}

    def calculate_array_disclosure(self, info):
        array_disclosure = self.upstream_get("context").claims.get_preference(
            "array_disclosure"
        )
        _discl = {}
        if array_disclosure:
            for k in array_disclosure:
                if k in info and len(info[k]) > 1:
                    _discl[k] = info[k]

        return _discl

    def matching_credentials_supported(self, request):
        _supported = self.upstream_get("context").claims.get_preference(
            "credentials_supported"
        )
        matching = []
        if _supported:
            for cs in _supported:
                if cs["format"] != request["format"]:
                    continue
                _cred_def_sup = cs["credential_definition"]
                _req_cred_def = request["credential_definition"]
                # The set of type values must match
                if set(_cred_def_sup["type"]) != set(_req_cred_def["type"]):
                    continue
                matching.append(_cred_def_sup.get("credentialSubject", {}))
        return matching

    def _must_display(self, disclose, must_display):
        for part, spec in disclose.items():
            if part == "":
                for key, val in spec.items():
                    _val = must_display.get(key)
                    if _val == val:
                        del must_display[key]
                    elif isinstance(_val, list) and val in _val:
                        _val.remove(val)
            else:
                _dict = must_display.get(part)
                if _dict:
                    for key, val in spec.items():
                        _val = _dict.get(key)
                        if _val == val:
                            del _dict[part][key]
                        elif isinstance(_val, list) and val in _val:
                            _val.remove(val)
                if dict == {}:
                    del must_display[part]
        return must_display

    def __call__(
        self,
        user_id: str,
        client_id: str,
        request: Union[dict, Message],
        auth_info: Optional[dict] = None,
        id_token: Optional[str] = None,
    ) -> str:
        logger.debug(":" * 20 + f"Credential constructor" + ":" * 20)

        # If an OP was used to handle the authentication then an id_token is provided
        # In the SAML case it's SATOSA internal_data.auth_info

        # compare what this entity supports with what is requested
        _matching = self.matching_credentials_supported(request)

        if _matching == []:
            raise RequestError("unsupported_credential_type")

        _cntxt = self.upstream_get("context")
        _mngr = _cntxt.session_manager

        # This is what the requester hopes to get
        if "credential_definition" in request:
            _req_cd = CredentialDefinition().from_dict(request["credential_definition"])
            csub = _req_cd.get("credentialSubject", {})
            if csub:
                _claims_restriction = {c: None for c in csub.keys()}
            else:
                _claims_restriction = {c: None for c in _matching[0].keys()}
        else:
            _claims_restriction = {c: None for c in _matching[0].keys()}

        logger.debug(f"claims_restriction: {_claims_restriction}")
        # Collect user info
        info = _cntxt.claims_interface.get_user_claims(
            user_id, claims_restriction=_claims_restriction, client_id=client_id
        )

        logger.debug(f"user claims [{user_id}]: {info}")

        # Initiate the Issuer
        ci = Issuer(
            key_jar=self.upstream_get("attribute", "keyjar"),
            iss=self.upstream_get("attribute", "entity_id"),
            sign_alg="ES256",
            lifetime=900,
            holder_key={},
        )
        must_display = info.copy()

        # First object disclosure
        _attribute_disclose = self.calculate_attribute_disclosure(info)

        if _attribute_disclose:
            # Figure out what must be displayed
            ci.objective_disclosure = _attribute_disclose
            must_display = self._must_display(_attribute_disclose, must_display)

        # Then array disclosure
        _array_disclosure = self.calculate_array_disclosure(info)
        if _array_disclosure:
            ci.array_disclosure = _array_disclosure

        # create SD-JWT
        return ci.create_holder_message(
            payload=must_display, jws_headers={"typ": "example+sd-jwt"}
        )


class Credential(Endpoint):
    response_cls = CredentialResponse
    request_cls = CredentialRequest
    error_msg = oidc.ResponseMessage
    request_format = "json"
    request_placement = "body"
    response_format = "json"
    response_placement = "body"
    endpoint_name = "credential_endpoint"
    name = "credential"
    endpoint_type = "oauth2"

    _supports = {
        "credentials_supported": None,
        "attribute_disclosure": None,
        "array_disclosure": None,
    }

    def __init__(self, upstream_get, conf=None, **kwargs):
        Endpoint.__init__(self, upstream_get, conf=conf, **kwargs)
        # dpop support
        self.post_parse_request.append(self.add_access_token_to_request)
        if conf and "credential_constructor" in conf:
            self.credential_constructor = execute(conf["credential_constructor"])
        else:
            self.credential_constructor = CredentialConstructor(
                upstream_get=upstream_get
            )

    def _get_session_info(self, endpoint_context, token):
        _jws = factory(token)
        if _jws:
            _sid = _jws.jwt.payload().get("sid")
            _info = endpoint_context.session_manager.get_session_info(session_id=_sid)
        else:
            _info = endpoint_context.session_manager.get_session_info_by_token(
                token, handler_key="access_token"
            )

        return _info

    def get_client_id_from_token(self, endpoint_context, token, request=None):
        _jws = factory(token)
        if _jws:
            _payload = _jws.jwt.payload()
            _client_id = _payload.get("client_id", "")
            if _client_id:
                return _client_id
            else:
                _sid = _jws.jwt.payload().get("sid")
                _info = endpoint_context.session_manager.get_session_info(
                    session_id=_sid
                )
        else:
            _info = endpoint_context.session_manager.get_session_info_by_token(
                token, handler_key="access_token"
            )

        return _info["client_id"]

    def add_access_token_to_request(self, request, client_id, context, **kwargs):
        request["access_token"] = kwargs["auth_info"]["token"]
        return request

    """ def process_request(self, request=None, **kwargs):
        logger.debug(f"process_request: {request}")

        try:
            _session_info = self._get_session_info(
                self.upstream_get("context"), request["access_token"]
            )
        except (KeyError, ValueError):
            return self.error_cls(
                error="invalid_token", error_description="Invalid Token"
            )

        _msg = self.credential_constructor(
            user_id=_session_info["user_id"],
            request=request,
            auth_info=_session_info["grant"].authentication_event,
            client_id=_session_info["client_id"],
        )

        _resp = {
            "format": "vc+sd-jwt",
            "credential": _msg,
            "c_nonce": rndstr(),
            "c_nonce_expires_in": 86400,
        }

        return {"response_args": _resp, "client_id": _session_info["client_id"]} """

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

    # gets the public key from a JWK
    def pKfromJWK(self, jwt_encoded):
        jwt_decoded = jwt.get_unverified_header(jwt_encoded)
        jwk = jwt_decoded["jwk"]

        if "crv" not in jwk or jwk["crv"] != "P-256":
            _resp = {
                "error": "invalid_proof",
                "error_description": "Credential Issuer only supports P-256 curves",
                "c_nonce": rndstr(),
                "c_nonce_expires_in": 86400,
            }
            return _resp  # {"response_args": _resp, "client_id": client_id}

        x = jwk["x"]
        y = jwk["y"]

        # Convert string coordinates to bytes
        x_bytes = base64.urlsafe_b64decode(x + "=" * (4 - len(x) % 4))
        y_bytes = base64.urlsafe_b64decode(y + "=" * (4 - len(y) % 4))

        # Create a public key from the bytes
        public_numbers = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(x_bytes, "big"),
            y=int.from_bytes(y_bytes, "big"),
            curve=ec.SECP256R1(),
        )

        public_key = public_numbers.public_key()

        # Serialize the public key to PEM format
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Encode the public key in base64url format

        device_key = base64.urlsafe_b64encode(public_key_pem).decode("utf-8")

        return device_key

    def pKfromCWT(self, cwt_encoded):
        decoded_cwt = cbor2.loads(base64.urlsafe_b64decode(cwt_encoded + "=="))

        if isinstance(decoded_cwt, cbor2.CBORTag):
            # print("CBORTag:", decoded_cwt)
            payload = decoded_cwt.value.value
        else:
            raise ValueError("Invalid CWT structure")

        sign1_message = Sign1Message.decode(cbor2.dumps(decoded_cwt.value))
        cose_key_dict = sign1_message.phdr["COSE_Key"]
        if isinstance(cose_key_dict, bytes):
            cose_key_dict = cbor2.loads(cose_key_dict)

        cose_key_1 = CoseKey.from_dict(cose_key_dict)

        payload = sign1_message.payload
        signature = sign1_message.signature

        # Verify the signature
        sign1_message.key = cose_key_1
        valid = sign1_message.verify_signature()

        if not valid:
            raise ValueError("Invalid CWT signature")

        cose_key_map = {1: ec.SECP256R1(), 2: ec.SECP384R1(), 3: ec.SECP521R1()}

        curve = cose_key_map[cose_key_dict[-1]]
        x = cose_key_dict[-2]
        y = cose_key_dict[-3]

        # Create a public key from the bytes
        public_numbers = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(x, "big"),
            y=int.from_bytes(y, "big"),
            curve=curve,
        )

        public_key = public_numbers.public_key()

        # Serialize the public key to PEM format
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Encode the public key in base64url format

        device_key = base64.urlsafe_b64encode(public_key_pem).decode("utf-8")

        return device_key

    def credentialReq(self, request, client_id):
        try:
            _mngr = self.upstream_get("context").session_manager
            _session_info = _mngr.get_session_info_by_token(
                request["access_token"], grant=True, handler_key="access_token"
            )
        except (KeyError, ValueError):
            _resp = {
                "error": "invalid_token",
                "error_description": "Invalid Token",
                "c_nonce": rndstr(),
                "c_nonce_expires_in": 86400,
            }
            return _resp

        for credential in request["credential_requests"]:
            if "jwt" in credential["proof"]:
                jwt_encoded = credential["proof"]["jwt"]
                device_key = self.pKfromJWK(jwt_encoded)
            elif "cwt" in credential["proof"]:
                cwt_encoded = credential["proof"]["cwt"]
                try:
                    device_key = self.pKfromCWT(cwt_encoded)
                except Exception as e:
                    _resp = {
                        "error": "invalid_proof",
                        "error_description": str(e),
                        "c_nonce": rndstr(),
                        "c_nonce_expires_in": 86400,
                    }
                    return _resp

            if "error" in device_key:
                return device_key, client_id
            credential["device_publickey"] = device_key
            credential.pop("proof")

        user_id = _session_info["user_id"]

        info = user_id.split(".", 1)

        # doc_country = request["doctype"] + "." + info[0]
        redirect_uri = request["oidc_config"].credential_urls["dynamic"]

        data = {
            "credential_requests": request["credential_requests"],
            "user_id": user_id,
        }

        json_data = json.dumps(data)
        headers = {"Content-Type": "application/json"}
        _msg = requests.post(redirect_uri, data=json_data, headers=headers).json()

        """ credentials = {"credential_responses": []}
        for credential in _msg:
            credentials["credential_responses"].append({credential: _msg[credential]}) """

        if "credential_responses" in _msg:
            if len(_msg["credential_responses"]) == 1:
                _msg = _msg["credential_responses"][0]

        _nonce = {
            "c_nonce": rndstr(),
            "c_nonce_expires_in": 86400,
        }

        _msg.update(_nonce)

        if "credential" in _msg or "credential_responses" in _msg:

            notification_id = rndstr()
            # transaction_id = rndstr()
            _session_info["grant"].add_notification(notification_id)
            # _session_info["grant"].add_transaction(transaction_id)

            _msg.update({"notification_id": notification_id})
            # _msg.update({"transaction_id": transaction_id})

            if "doctype" in data["credential_requests"][0]:
                if (
                    data["credential_requests"][0]["doctype"]
                    == "eu.europa.ec.eudi.pseudonym.age_over_18.deferred_endpoint"
                    and "transaction_id" not in request
                ):
                    transaction_id = rndstr()
                    _session_info["grant"].add_transaction(transaction_id, None)
                    _msg = {
                        "transaction_id": transaction_id,
                        "c_nonce": rndstr(),
                        "c_nonce_expires_in": 86400,
                    }

            if "transaction_id" in request:
                _session_info["grant"].add_transaction(request["transaction_id"], _msg)

        else:
            if "transaction_id" in request:
                _msg.update({"transaction_id": request["transaction_id"]})
            elif "error" in _msg and _msg["error"] == "Pending":
                transaction_id = rndstr()
                _session_info["grant"].add_transaction(transaction_id, None)
                _msg.update({"transaction_id": transaction_id})
                _msg.pop("error")
            else:
                _resp = {
                    "error": "invalid_credential_request",
                    "error_description": "Couldn't generate credential",
                    "c_nonce": rndstr(),
                    "c_nonce_expires_in": 86400,
                }
                return _resp

        return _msg

    def process_request(self, request=None, **kwargs):
        # _msg = self.credential_constructor(
        #    user_id=_session_info["user_id"], request=request
        # )

        tokenAuthResult = self.verify_token_and_authentication(request)
        if "error" in tokenAuthResult:
            return tokenAuthResult

        allowed, client_id = tokenAuthResult
        if not isinstance(allowed, bool):
            return allowed

        if not allowed:
            return {
                "response_args": {
                    "c_nonce": rndstr(),
                    "c_nonce_expires_in": 86400,
                    "error": "invalid_token",
                    "error_description": "Access not granted",
                },
                "client_id": client_id,
            }

        if "format" in request and not ("vct" in request or "doctype" in request):
            return {
                "response_args": {
                    "c_nonce": rndstr(),
                    "c_nonce_expires_in": 86400,
                    "error": "invalid_credential_request",
                    "error_description": "Missing doctype or vct",
                },
                "client_id": client_id,
            }

        if "credential_requests" in request:
            for credential in request["credential_requests"]:
                if "proof" not in credential:
                    return {
                        "response_args": {
                            "c_nonce": rndstr(),
                            "c_nonce_expires_in": 86400,
                            "error": "invalid_proof",
                            "error_description": "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.",
                        },
                        "client_id": client_id,
                    }

                elif "proof" in credential:
                    if "proof_type" not in credential["proof"]:
                        return {
                            "response_args": {
                                "c_nonce": rndstr(),
                                "c_nonce_expires_in": 86400,
                                "error": "invalid_proof",
                                "error_description": "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.",
                            },
                            "client_id": client_id,
                        }
                    """ if "jwt" not in credential["proof"]:
                        return {
                            "response_args": {
                                "c_nonce": rndstr(),
                                "c_nonce_expires_in": 86400,
                                "error": "invalid_proof",
                                "error_description": "Only JWT and CWT supported at this time",
                            },
                            "client_id": client_id,
                        } """
                    if (
                        credential["proof"]["proof_type"] == "jwt"
                        and "jwt" not in credential["proof"]
                    ):
                        return {
                            "response_args": {
                                "c_nonce": rndstr(),
                                "c_nonce_expires_in": 86400,
                                "error": "invalid_proof",
                                "error_description": "Missing jwt field",
                            },
                            "client_id": client_id,
                        }
                    if (
                        credential["proof"]["proof_type"] == "cwt"
                        and "cwt" not in credential["proof"]
                    ):
                        return {
                            "response_args": {
                                "c_nonce": rndstr(),
                                "c_nonce_expires_in": 86400,
                                "error": "invalid_proof",
                                "error_description": "Missing cwt field",
                            },
                            "client_id": client_id,
                        }

                if "oidc_config" not in request:
                    return {
                        "response_args": {
                            "c_nonce": rndstr(),
                            "c_nonce_expires_in": 86400,
                            "error": "invalid_credential_request",
                            "error_description": "Internal missing oidc config",
                        },
                        "client_id": client_id,
                    }

        elif "proof" not in request:
            return {
                "response_args": {
                    "c_nonce": rndstr(),
                    "c_nonce_expires_in": 86400,
                    "error": "invalid_proof",
                    "error_description": "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.",
                },
                "client_id": client_id,
            }
        elif "proof" in request:
            if "proof_type" not in request["proof"]:
                return {
                    "response_args": {
                        "c_nonce": rndstr(),
                        "c_nonce_expires_in": 86400,
                        "error": "invalid_proof",
                        "error_description": "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.",
                    },
                    "client_id": client_id,
                }
            """ if "jwt" not in request["proof"]:
                return {
                    "response_args": {
                        "c_nonce": rndstr(),
                        "c_nonce_expires_in": 86400,
                        "error": "invalid_proof",
                        "error_description": "Only JWT and CWT supported at this time",
                    },
                    "client_id": client_id,
                } """
            if (
                request["proof"]["proof_type"] == "jwt"
                and "jwt" not in request["proof"]
            ):
                return {
                    "response_args": {
                        "c_nonce": rndstr(),
                        "c_nonce_expires_in": 86400,
                        "error": "invalid_proof",
                        "error_description": "Missing jwt field",
                    },
                    "client_id": client_id,
                }
            if (
                request["proof"]["proof_type"] == "cwt"
                and "cwt" not in request["proof"]
            ):
                return {
                    "response_args": {
                        "c_nonce": rndstr(),
                        "c_nonce_expires_in": 86400,
                        "error": "invalid_proof",
                        "error_description": "Missing cwt field",
                    },
                    "client_id": client_id,
                }

        req = request

        if (
            "credential_requests" not in request
            and "format" in request
            and "doctype" in request
            and "proof" in request
        ):
            credential_json = {
                "format": request["format"],
                "doctype": request["doctype"],
                "proof": request["proof"],
            }

            req = {"credential_requests": [credential_json]}
            request.pop("format")
            request.pop("doctype")
            request.pop("proof")

            request.update(req)

        elif (
            "credential_requests" not in request
            and "format" in request
            and "vct" in request
            and "proof" in request
        ):
            credential_json = {
                "format": request["format"],
                "vct": request["vct"],
                "proof": request["proof"],
            }

            req = {"credential_requests": [credential_json]}
            request.pop("format")
            request.pop("vct")
            request.pop("proof")

            request.update(req)

        elif (
            "credential_requests" not in request
            and "format" not in request
            and "credential_identifier" in request
            and "proof" in request
        ):
            credential_json = {
                "format": request["format"],
                "credential_identifier": request["credential_identifier"],
                "proof": request["proof"],
            }

            req = {"credential_requests": [credential_json]}
            request.pop("format")
            request.pop("credential_identifier")
            request.pop("proof")

            request.update(req)

        elif "credential_requests" not in request:
            return {
                "response_args": {
                    "c_nonce": rndstr(),
                    "c_nonce_expires_in": 86400,
                    "error": "invalid_credential_request",
                    "error_description": "Missing or mismatched data",
                },
                "client_id": client_id,
            }

        _resp = self.credentialReq(request, client_id)

        # credentials, client_id = self.credentialReq(request)

        logger.info("Response: ", _resp)

        return {"response_args": _resp, "client_id": client_id}
