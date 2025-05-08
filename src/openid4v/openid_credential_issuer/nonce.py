import json
from flask import make_response
from idpyoidc.server.oidc.userinfo import UserInfo
from authlib.jose import JsonWebEncryption
import time


class Nonce(UserInfo):
    endpoint_name = "nonce_endpoint"
    name = "nonce"

    def __init__(self, upstream_get, conf=None, **kwargs):
        UserInfo.__init__(self, upstream_get, conf=conf, **kwargs)

    def process_request(self, request=None, **kwargs):
        if "key_path" not in request:
            return self.error_cls(
                error="failed request", error_description="missing_jwt_key"
            )

        protected = {"type": "cnonce+jwt", "alg": "RSA-OAEP", "enc": "A256GCM"}
        with open(request["key_path"], "rb") as f:
            key = f.read()

        current_time = int(time.time())

        payload = {
            "iss": request["iss"],
            "iat": current_time,
            "exp": current_time + 3600,
            "source_endpoint": request["source_endpoint"],
            "aud": request["aud"],
        }

        jwe = JsonWebEncryption()

        payload_json = json.dumps(payload)

        encrypted_jwt = jwe.serialize_compact(protected, payload_json, key)

        data = jwe.deserialize_compact(encrypted_jwt, key)
        jwe_payload = data["payload"]

        response = {"c_nonce": encrypted_jwt.decode("utf-8")}

        return make_response(response, 200)
