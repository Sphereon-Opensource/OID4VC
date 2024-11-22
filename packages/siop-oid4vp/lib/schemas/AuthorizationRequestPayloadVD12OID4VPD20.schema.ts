export const AuthorizationRequestPayloadVD12OID4VPD20SchemaObj = {
  "$id": "AuthorizationRequestPayloadVD12OID4VPD20Schema",
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$ref": "#/definitions/AuthorizationRequestPayloadVD12OID4VPD20",
  "definitions": {
    "AuthorizationRequestPayloadVD12OID4VPD20": {
      "type": "object",
      "properties": {
        "id_token_type": {
          "type": "string"
        },
        "client_metadata": {
          "$ref": "#/definitions/RPRegistrationMetadataPayload"
        },
        "client_metadata_uri": {
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
          "$ref": "#/definitions/ClaimPayloadCommon"
        },
        "presentation_definition": {
          "anyOf": [
            {
              "$ref": "#/definitions/PresentationDefinitionV1"
            },
            {
              "$ref": "#/definitions/PresentationDefinitionV2"
            },
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/PresentationDefinitionV1"
              }
            },
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/PresentationDefinitionV2"
              }
            }
          ]
        },
        "presentation_definition_uri": {
          "type": "string"
        },
        "client_id_scheme": {
          "$ref": "#/definitions/ClientIdSchemeOID4VPD20"
        },
        "response_uri": {
          "type": "string"
        }
      }
    },
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
    "ClaimPayloadCommon": {
      "type": "object"
    },
    "PresentationDefinitionV1": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "purpose": {
          "type": "string"
        },
        "format": {
          "$ref": "#/definitions/Format"
        },
        "submission_requirements": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/SubmissionRequirement"
          }
        },
        "input_descriptors": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/InputDescriptorV1"
          }
        }
      },
      "required": [
        "id",
        "input_descriptors"
      ],
      "additionalProperties": false
    },
    "SubmissionRequirement": {
      "type": "object",
      "properties": {
        "name": {
          "type": "string"
        },
        "purpose": {
          "type": "string"
        },
        "rule": {
          "$ref": "#/definitions/Rules"
        },
        "count": {
          "type": "number"
        },
        "min": {
          "type": "number"
        },
        "max": {
          "type": "number"
        },
        "from": {
          "type": "string"
        },
        "from_nested": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/SubmissionRequirement"
          }
        }
      },
      "required": [
        "rule"
      ],
      "additionalProperties": false
    },
    "Rules": {
      "type": "string",
      "enum": [
        "all",
        "pick"
      ]
    },
    "InputDescriptorV1": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "purpose": {
          "type": "string"
        },
        "group": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "schema": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/Schema"
          }
        },
        "issuance": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/Issuance"
          }
        },
        "constraints": {
          "$ref": "#/definitions/ConstraintsV1"
        }
      },
      "required": [
        "id",
        "schema"
      ],
      "additionalProperties": false
    },
    "Schema": {
      "type": "object",
      "properties": {
        "uri": {
          "type": "string"
        },
        "required": {
          "type": "boolean"
        }
      },
      "required": [
        "uri"
      ],
      "additionalProperties": false
    },
    "Issuance": {
      "type": "object",
      "properties": {
        "manifest": {
          "type": "string"
        }
      },
      "additionalProperties": {}
    },
    "ConstraintsV1": {
      "type": "object",
      "properties": {
        "limit_disclosure": {
          "$ref": "#/definitions/Optionality"
        },
        "statuses": {
          "$ref": "#/definitions/Statuses"
        },
        "fields": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/FieldV1"
          }
        },
        "subject_is_issuer": {
          "$ref": "#/definitions/Optionality"
        },
        "is_holder": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/HolderSubject"
          }
        },
        "same_subject": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/HolderSubject"
          }
        }
      },
      "additionalProperties": false
    },
    "Optionality": {
      "type": "string",
      "enum": [
        "required",
        "preferred"
      ]
    },
    "Statuses": {
      "type": "object",
      "properties": {
        "active": {
          "$ref": "#/definitions/PdStatus"
        },
        "suspended": {
          "$ref": "#/definitions/PdStatus"
        },
        "revoked": {
          "$ref": "#/definitions/PdStatus"
        }
      },
      "additionalProperties": false
    },
    "PdStatus": {
      "type": "object",
      "properties": {
        "directive": {
          "$ref": "#/definitions/Directives"
        }
      },
      "additionalProperties": false
    },
    "Directives": {
      "type": "string",
      "enum": [
        "required",
        "allowed",
        "disallowed"
      ]
    },
    "FieldV1": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "path": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "purpose": {
          "type": "string"
        },
        "filter": {
          "$ref": "#/definitions/FilterV1"
        },
        "predicate": {
          "$ref": "#/definitions/Optionality"
        }
      },
      "required": [
        "path"
      ],
      "additionalProperties": false
    },
    "FilterV1": {
      "type": "object",
      "properties": {
        "const": {
          "$ref": "#/definitions/OneOfNumberStringBoolean"
        },
        "enum": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/OneOfNumberStringBoolean"
          }
        },
        "exclusiveMinimum": {
          "$ref": "#/definitions/OneOfNumberString"
        },
        "exclusiveMaximum": {
          "$ref": "#/definitions/OneOfNumberString"
        },
        "format": {
          "type": "string"
        },
        "minLength": {
          "type": "number"
        },
        "maxLength": {
          "type": "number"
        },
        "minimum": {
          "$ref": "#/definitions/OneOfNumberString"
        },
        "maximum": {
          "$ref": "#/definitions/OneOfNumberString"
        },
        "not": {
          "type": "object"
        },
        "pattern": {
          "type": "string"
        },
        "type": {
          "type": "string"
        }
      },
      "required": [
        "type"
      ],
      "additionalProperties": false
    },
    "OneOfNumberStringBoolean": {
      "type": [
        "boolean",
        "number",
        "string"
      ]
    },
    "OneOfNumberString": {
      "type": [
        "number",
        "string"
      ]
    },
    "HolderSubject": {
      "type": "object",
      "properties": {
        "field_id": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "directive": {
          "$ref": "#/definitions/Optionality"
        }
      },
      "required": [
        "field_id",
        "directive"
      ],
      "additionalProperties": false
    },
    "PresentationDefinitionV2": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "purpose": {
          "type": "string"
        },
        "format": {
          "$ref": "#/definitions/Format"
        },
        "submission_requirements": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/SubmissionRequirement"
          }
        },
        "input_descriptors": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/InputDescriptorV2"
          }
        },
        "frame": {
          "type": "object"
        }
      },
      "required": [
        "id",
        "input_descriptors"
      ],
      "additionalProperties": false
    },
    "InputDescriptorV2": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "purpose": {
          "type": "string"
        },
        "format": {
          "$ref": "#/definitions/Format"
        },
        "group": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "issuance": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/Issuance"
          }
        },
        "constraints": {
          "$ref": "#/definitions/ConstraintsV2"
        }
      },
      "required": [
        "id",
        "constraints"
      ],
      "additionalProperties": false
    },
    "ConstraintsV2": {
      "type": "object",
      "properties": {
        "limit_disclosure": {
          "$ref": "#/definitions/Optionality"
        },
        "statuses": {
          "$ref": "#/definitions/Statuses"
        },
        "fields": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/FieldV2"
          }
        },
        "subject_is_issuer": {
          "$ref": "#/definitions/Optionality"
        },
        "is_holder": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/HolderSubject"
          }
        },
        "same_subject": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/HolderSubject"
          }
        }
      },
      "additionalProperties": false
    },
    "FieldV2": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "path": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "purpose": {
          "type": "string"
        },
        "filter": {
          "$ref": "#/definitions/FilterV2"
        },
        "predicate": {
          "$ref": "#/definitions/Optionality"
        },
        "intent_to_retain": {
          "type": "boolean"
        },
        "name": {
          "type": "string"
        },
        "optional": {
          "type": "boolean"
        }
      },
      "required": [
        "path"
      ],
      "additionalProperties": false
    },
    "FilterV2": {
      "type": "object",
      "properties": {
        "const": {
          "$ref": "#/definitions/OneOfNumberStringBoolean"
        },
        "enum": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/OneOfNumberStringBoolean"
          }
        },
        "exclusiveMinimum": {
          "$ref": "#/definitions/OneOfNumberString"
        },
        "exclusiveMaximum": {
          "$ref": "#/definitions/OneOfNumberString"
        },
        "format": {
          "type": "string"
        },
        "formatMaximum": {
          "type": "string"
        },
        "formatMinimum": {
          "type": "string"
        },
        "formatExclusiveMaximum": {
          "type": "string"
        },
        "formatExclusiveMinimum": {
          "type": "string"
        },
        "minLength": {
          "type": "number"
        },
        "maxLength": {
          "type": "number"
        },
        "minimum": {
          "$ref": "#/definitions/OneOfNumberString"
        },
        "maximum": {
          "$ref": "#/definitions/OneOfNumberString"
        },
        "not": {
          "type": "object"
        },
        "pattern": {
          "type": "string"
        },
        "type": {
          "type": "string"
        },
        "contains": {
          "$ref": "#/definitions/FilterV2Base"
        },
        "items": {
          "$ref": "#/definitions/FilterV2BaseItems"
        }
      },
      "required": [
        "type"
      ],
      "additionalProperties": false
    },
    "FilterV2Base": {
      "type": "object",
      "properties": {
        "const": {
          "$ref": "#/definitions/OneOfNumberStringBoolean"
        },
        "enum": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/OneOfNumberStringBoolean"
          }
        },
        "exclusiveMinimum": {
          "$ref": "#/definitions/OneOfNumberString"
        },
        "exclusiveMaximum": {
          "$ref": "#/definitions/OneOfNumberString"
        },
        "format": {
          "type": "string"
        },
        "formatMaximum": {
          "type": "string"
        },
        "formatMinimum": {
          "type": "string"
        },
        "formatExclusiveMaximum": {
          "type": "string"
        },
        "formatExclusiveMinimum": {
          "type": "string"
        },
        "minLength": {
          "type": "number"
        },
        "maxLength": {
          "type": "number"
        },
        "minimum": {
          "$ref": "#/definitions/OneOfNumberString"
        },
        "maximum": {
          "$ref": "#/definitions/OneOfNumberString"
        },
        "not": {
          "type": "object"
        },
        "pattern": {
          "type": "string"
        },
        "type": {
          "type": "string"
        },
        "contains": {
          "$ref": "#/definitions/FilterV2Base"
        },
        "items": {
          "$ref": "#/definitions/FilterV2BaseItems"
        }
      },
      "additionalProperties": false
    },
    "FilterV2BaseItems": {
      "type": "object",
      "properties": {
        "const": {
          "$ref": "#/definitions/OneOfNumberStringBoolean"
        },
        "enum": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/OneOfNumberStringBoolean"
          }
        },
        "exclusiveMinimum": {
          "$ref": "#/definitions/OneOfNumberString"
        },
        "exclusiveMaximum": {
          "$ref": "#/definitions/OneOfNumberString"
        },
        "format": {
          "type": "string"
        },
        "formatMaximum": {
          "type": "string"
        },
        "formatMinimum": {
          "type": "string"
        },
        "formatExclusiveMaximum": {
          "type": "string"
        },
        "formatExclusiveMinimum": {
          "type": "string"
        },
        "minLength": {
          "type": "number"
        },
        "maxLength": {
          "type": "number"
        },
        "minimum": {
          "$ref": "#/definitions/OneOfNumberString"
        },
        "maximum": {
          "$ref": "#/definitions/OneOfNumberString"
        },
        "not": {
          "type": "object"
        },
        "pattern": {
          "type": "string"
        },
        "type": {
          "type": "string"
        },
        "contains": {
          "$ref": "#/definitions/FilterV2Base"
        },
        "items": {
          "$ref": "#/definitions/FilterV2BaseItems"
        }
      },
      "required": [
        "type"
      ],
      "additionalProperties": false
    },
    "ClientIdSchemeOID4VPD20": {
      "anyOf": [
        {
          "$ref": "#/definitions/ClientIdSchemeOID4VPD18"
        },
        {
          "type": "string",
          "const": "x509_san_dns"
        },
        {
          "type": "string",
          "const": "x509_san_uri"
        },
        {
          "type": "string",
          "const": "entity_id"
        },
        {
          "type": "string",
          "const": "verifier_attestation"
        }
      ]
    },
    "ClientIdSchemeOID4VPD18": {
      "type": "string",
      "enum": [
        "pre-registered",
        "redirect_uri",
        "entity_id",
        "did"
      ]
    }
  }
};