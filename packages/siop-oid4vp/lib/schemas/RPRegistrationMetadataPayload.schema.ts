export const RPRegistrationMetadataPayloadSchemaObj = {
  "$id": "RPRegistrationMetadataPayloadSchema",
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$ref": "#/definitions/RPRegistrationMetadataPayload",
  "definitions": {
    "RPRegistrationMetadataPayload": {
      "type": "object",
      "properties": {
        "federation_entity": {
          "$ref": "#/definitions/FederationEntityMetadataPayload"
        },
        "openid_credential_verifier": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "vp_formats": {
              "$ref": "#/definitions/Format"
            },
            "redirect_uris": {
              "type": "array",
              "items": {
                "type": "string"
              }
            },
            "token_endpoint_auth_method": {
              "type": "string"
            },
            "grant_types": {
              "type": "string"
            },
            "response_types": {
              "type": "string"
            },
            "client_name": {
              "type": "string"
            },
            "client_uri": {
              "type": "string"
            },
            "logo_uri": {
              "type": "string"
            },
            "scope": {
              "type": "string"
            },
            "contacts": {
              "type": "array",
              "items": {
                "type": "string"
              }
            },
            "tos_uri": {
              "type": "string"
            },
            "policy_uri": {
              "type": "string"
            },
            "jwks_uri": {
              "type": "string"
            },
            "jwks": {
              "$ref": "#/definitions/JWKS"
            },
            "software_id": {
              "type": "string"
            },
            "software_version": {
              "type": "string"
            }
          },
          "required": [
            "vp_formats"
          ]
        },
        "client_id": {
          "anyOf": [
            {
              "type": "string"
            },
            {}
          ]
        },
        "id_token_signing_alg_values_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/SigningAlgo"
              }
            },
            {
              "$ref": "#/definitions/SigningAlgo"
            }
          ]
        },
        "request_object_signing_alg_values_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/SigningAlgo"
              }
            },
            {
              "$ref": "#/definitions/SigningAlgo"
            }
          ]
        },
        "response_types_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/ResponseType"
              }
            },
            {
              "$ref": "#/definitions/ResponseType"
            }
          ]
        },
        "scopes_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/Scope"
              }
            },
            {
              "$ref": "#/definitions/Scope"
            }
          ]
        },
        "subject_types_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/SubjectType"
              }
            },
            {
              "$ref": "#/definitions/SubjectType"
            }
          ]
        },
        "subject_syntax_types_supported": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "vp_formats": {
          "anyOf": [
            {
              "$ref": "#/definitions/Format"
            },
            {}
          ]
        },
        "client_name": {
          "anyOf": [
            {
              "type": "string"
            },
            {}
          ]
        },
        "logo_uri": {
          "anyOf": [
            {
              "type": "string"
            },
            {}
          ]
        },
        "client_purpose": {
          "anyOf": [
            {},
            {
              "type": "string"
            }
          ]
        }
      }
    },
    "FederationEntityMetadataPayload": {
      "type": "object",
      "properties": {
        "federation_fetch_endpoint": {
          "type": "string"
        },
        "federation_list_endpoint": {
          "type": "string"
        },
        "federation_resolve_endpoint": {
          "type": "string"
        },
        "federation_trust_mark_status_endpoint": {
          "type": "string"
        },
        "federation_trust_mark_list_endpoint": {
          "type": "string"
        },
        "federation_trust_mark_endpoint": {
          "type": "string"
        },
        "federation_historical_keys_endpoint": {
          "type": "string"
        },
        "organization_name": {
          "type": "string"
        },
        "homepage_uri": {
          "type": "string"
        }
      },
      "additionalProperties": false
    },
    "Format": {
      "type": "object",
      "properties": {
        "jwt": {
          "$ref": "#/definitions/JwtObject"
        },
        "jwt_vc": {
          "$ref": "#/definitions/JwtObject"
        },
        "jwt_vc_json": {
          "$ref": "#/definitions/JwtObject"
        },
        "jwt_vp": {
          "$ref": "#/definitions/JwtObject"
        },
        "jwt_vp_json": {
          "$ref": "#/definitions/JwtObject"
        },
        "ldp": {
          "$ref": "#/definitions/LdpObject"
        },
        "ldp_vc": {
          "$ref": "#/definitions/LdpObject"
        },
        "ldp_vp": {
          "$ref": "#/definitions/LdpObject"
        },
        "di": {
          "$ref": "#/definitions/DiObject"
        },
        "di_vc": {
          "$ref": "#/definitions/DiObject"
        },
        "di_vp": {
          "$ref": "#/definitions/DiObject"
        },
        "vc+sd-jwt": {
          "$ref": "#/definitions/SdJwtObject"
        },
        "mso_mdoc": {
          "$ref": "#/definitions/MsoMdocObject"
        }
      },
      "additionalProperties": false
    },
    "JwtObject": {
      "type": "object",
      "properties": {
        "alg": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "alg"
      ],
      "additionalProperties": false
    },
    "LdpObject": {
      "type": "object",
      "properties": {
        "proof_type": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "proof_type"
      ],
      "additionalProperties": false
    },
    "DiObject": {
      "type": "object",
      "properties": {
        "proof_type": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "cryptosuite": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "proof_type",
        "cryptosuite"
      ],
      "additionalProperties": false
    },
    "SdJwtObject": {
      "type": "object",
      "properties": {
        "sd-jwt_alg_values": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "kb-jwt_alg_values": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "additionalProperties": false
    },
    "MsoMdocObject": {
      "type": "object",
      "properties": {
        "alg": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "alg"
      ],
      "additionalProperties": false
    },
    "JWKS": {
      "type": "object",
      "properties": {
        "keys": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/JWK"
          }
        }
      },
      "required": [
        "keys"
      ],
      "additionalProperties": false
    },
    "JWK": {
      "type": "object",
      "properties": {
        "kty": {
          "type": "string"
        },
        "crv": {
          "type": "string"
        },
        "x": {
          "type": "string"
        },
        "y": {
          "type": "string"
        },
        "e": {
          "type": "string"
        },
        "n": {
          "type": "string"
        },
        "alg": {
          "type": "string"
        },
        "d": {
          "type": "string"
        },
        "dp": {
          "type": "string"
        },
        "dq": {
          "type": "string"
        },
        "ext": {
          "type": "boolean"
        },
        "k": {
          "type": "string"
        },
        "key_ops": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "kid": {
          "type": "string"
        },
        "oth": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "d": {
                "type": "string"
              },
              "r": {
                "type": "string"
              },
              "t": {
                "type": "string"
              }
            },
            "additionalProperties": false
          }
        },
        "p": {
          "type": "string"
        },
        "q": {
          "type": "string"
        },
        "qi": {
          "type": "string"
        },
        "use": {
          "type": "string"
        },
        "x5c": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "x5t": {
          "type": "string"
        },
        "x5t#S256": {
          "type": "string"
        },
        "x5u": {
          "type": "string"
        }
      },
      "additionalProperties": {}
    },
    "SigningAlgo": {
      "type": "string",
      "enum": [
        "EdDSA",
        "RS256",
        "PS256",
        "ES256",
        "ES256K"
      ]
    },
    "ResponseType": {
      "type": "string",
      "enum": [
        "id_token",
        "vp_token"
      ]
    },
    "Scope": {
      "type": "string",
      "enum": [
        "openid",
        "openid did_authn",
        "profile",
        "email",
        "address",
        "phone"
      ]
    },
    "SubjectType": {
      "type": "string",
      "enum": [
        "public",
        "pairwise"
      ]
    }
  }
};