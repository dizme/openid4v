from fedservice.utils import make_federation_combo
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.oauth2 import Client

from openid4v.client.client_authn import ClientAssertion
from openid4v.client.pid_eaa_consumer import PidEaaHandler
from openid4v.client.wallet_instance_attestation import WalletInstanceAttestation


def test_create():
    entity = make_federation_combo(
        'https://rp.example.org',
        key_config={'key_defs': [{'type': 'RSA', 'use': ['sig']},
                                 {'type': 'EC', 'crv': 'P-256', 'use': ['sig']}]},
        preference={'organization_name': 'The RP',
                    'homepage_uri': 'https://rp.example.com',
                    'contacts': 'operations@rp.example.com'},
        authority_hints=['https://im1.example.org'],
        services=["entity_configuration", "entity_statement", "trust_mark_status",
                  "resolve", "list"],
        functions=["trust_chain_collector", "verifier", "policy", "trust_mark_verifier"],
        entity_type={
            "wallet": {
                'class': Client,
                'kwargs': {
                    'config': {
                        "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                        "services": {
                            "wallet_instance_attestation": {
                                "class": WalletInstanceAttestation,
                                "kwargs": {}
                            }
                        },
                        "wallet_provider_id": "https://wp.example.com"
                    }
                }
            },
            "pid_eaa_handler": {
                'class': PidEaaHandler,
                'kwargs': {
                    'config': {
                        "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                        "base_url": "",
                        "add_ons": {
                            "pkce": {
                                "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
                                "kwargs": {"code_challenge_length": 64,
                                           "code_challenge_method": "S256"},
                            },
                            "dpop": {
                                "function": "idpyoidc.client.oauth2.add_on.dpop.add_support",
                                "kwargs": {
                                    'dpop_signing_alg_values_supported': ["ES256"]
                                }
                            },
                            "pushed_authorization": {
                                "function": "idpyoidc.client.oauth2.add_on.par.add_support",
                                "kwargs": {
                                    "body_format": "jws",
                                    "signing_algorithm": "RS256",
                                    "http_client": None,
                                    "merge_rule": "lax",
                                },
                            }
                        },
                        "services": {
                            "pid_eaa_authorization": {
                                "class": "openid4v.client.pid_eaa.Authorization",
                                "kwargs": {
                                    "response_types_supported": ["code"],
                                    "response_modes_supported": ["query", "form_post"],
                                    "request_parameter_supported": True,
                                    "request_uri_parameter_supported": True,
                                    "client_authn_methods": {"client_assertion": ClientAssertion}
                                },
                            },
                            "pid_eaa_token": {
                                "class": "openid4v.client.pid_eaa.AccessToken",
                                "kwargs": {}
                            },
                            "credential": {
                                "path": "credential",
                                "class": "openid4v.client.pid_eaa.Credential",
                                "kwargs": {},
                            }
                        }
                    }
                }
            }
        }
    )
    handler = entity["pid_eaa_handler"]
    handler.new_consumer("https://wp.example.org")
    assert handler.get_consumer("https://wp.example.org")
