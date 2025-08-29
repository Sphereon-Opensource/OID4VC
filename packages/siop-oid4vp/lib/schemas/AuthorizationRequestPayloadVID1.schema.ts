export const AuthorizationRequestPayloadVID1SchemaObj = {
  "$id": "AuthorizationRequestPayloadVID1Schema",
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$ref": "#/definitions/AuthorizationRequestPayloadVID1",
  "definitions": {
    "AuthorizationRequestPayloadVID1": {
      "type": "object",
      "properties": {
        "registration": {
          "$ref": "#/definitions/RPRegistrationMetadataPayload"
        },
        "registration_uri": {
          "type": "string"
        },
        "iss": {
          "type": "string"
        },
        "sub": {
          "type": "string"
        },
        "aud": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "array",
              "items": {
                "type": "string"
              }
            }
          ]
        },
        "iat": {
          "type": "number"
        },
        "nbf": {
          "type": "number"
        },
        "type": {
          "type": "string"
        },
        "exp": {
          "type": "number"
        },
        "rexp": {
          "type": "number"
        },
        "jti": {
          "type": "string"
        },
        "scope": {
          "type": "string"
        },
        "response_type": {
          "anyOf": [
            {
              "$ref": "#/definitions/ResponseType"
            },
            {
              "type": "string"
            }
          ]
        },
        "client_id": {
          "type": "string"
        },
        "redirect_uri": {
          "type": "string"
        },
        "id_token_hint": {
          "type": "string"
        },
        "nonce": {
          "type": "string"
        },
        "state": {
          "type": "string"
        },
        "response_mode": {
          "$ref": "#/definitions/ResponseMode"
        },
        "request": {
          "type": "string"
        },
        "request_uri": {
          "type": "string"
        },
        "claims": {
          "$ref": "#/definitions/ClaimPayloadVID1"
        }
      }
    },
    "RPRegistrationMetadataPayload": {
      "type": "object",
      "properties": {
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
                "type": "string",
                "enum": [
                  "EdDSA",
                  "RS256",
                  "PS256",
                  "ES256",
                  "ES256K"
                ]
              }
            },
            {
              "type": "string",
              "enum": [
                "EdDSA",
                "RS256",
                "PS256",
                "ES256",
                "ES256K"
              ]
            }
          ]
        },
        "request_object_signing_alg_values_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "type": "string",
                "enum": [
                  "EdDSA",
                  "RS256",
                  "PS256",
                  "ES256",
                  "ES256K"
                ]
              }
            },
            {
              "type": "string",
              "enum": [
                "EdDSA",
                "RS256",
                "PS256",
                "ES256",
                "ES256K"
              ]
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
        "vp_formats_supported": {
          "anyOf": [
            {},
            {
              "$ref": "#/definitions/Format"
            }
          ]
        },
        "client_name": {
          "type": "string"
        },
        "logo_uri": {
          "type": "string"
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
    "ResponseMode": {
      "type": "string",
      "enum": [
        "fragment",
        "form_post",
        "post",
        "direct_post",
        "query",
        "direct_post.jwt",
        "query.jwt",
        "fragment.jwt"
      ]
    },
    "ClaimPayloadVID1": {
      "type": "object",
      "properties": {
        "id_token": {
          "$ref": "#/definitions/IdTokenClaimPayload"
        },
        "vp_token": {
          "$ref": "#/definitions/VpTokenClaimPayload"
        }
      }
    },
    "IdTokenClaimPayload": {
      "type": "object"
    },
    "VpTokenClaimPayload": {
      "type": "object",
      "properties": {
        "dcql_query": {
          "type": "string"
        }
      },
      "additionalProperties": false
    }
  }
};