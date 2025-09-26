export const RPRegistrationMetadataPayloadSchemaObj = {
  "$id": "RPRegistrationMetadataPayloadSchema",
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$ref": "#/definitions/RPRegistrationMetadataPayload",
  "definitions": {
    "RPRegistrationMetadataPayload": {
      "type": "object",
      "properties": {
        "client_id": {
          "type": "string"
        },
        "client_purpose": {
          "type": "string"
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
          "type": "object",
          "properties": {
            "jwt": {
              "type": "object",
              "properties": {
                "alg_values": {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                }
              },
              "required": [
                "alg_values"
              ],
              "additionalProperties": false
            },
            "jwt_vc": {
              "type": "object",
              "properties": {
                "alg_values": {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                }
              },
              "required": [
                "alg_values"
              ],
              "additionalProperties": false
            },
            "jwt_vc_json": {
              "type": "object",
              "properties": {
                "alg_values": {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                }
              },
              "required": [
                "alg_values"
              ],
              "additionalProperties": false
            },
            "jwt_vp": {
              "type": "object",
              "properties": {
                "alg_values": {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                }
              },
              "required": [
                "alg_values"
              ],
              "additionalProperties": false
            },
            "jwt_vp_json": {
              "type": "object",
              "properties": {
                "alg_values": {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                }
              },
              "required": [
                "alg_values"
              ],
              "additionalProperties": false
            },
            "ldp": {
              "type": "object",
              "properties": {
                "proof_type_values": {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                }
              },
              "required": [
                "proof_type_values"
              ],
              "additionalProperties": false
            },
            "ldp_vc": {
              "type": "object",
              "properties": {
                "proof_type_values": {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                }
              },
              "required": [
                "proof_type_values"
              ],
              "additionalProperties": false
            },
            "ldp_vp": {
              "type": "object",
              "properties": {
                "proof_type_values": {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                }
              },
              "required": [
                "proof_type_values"
              ],
              "additionalProperties": false
            },
            "di": {
              "type": "object",
              "properties": {
                "proof_type_values": {
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
                "proof_type_values",
                "cryptosuite"
              ],
              "additionalProperties": false
            },
            "di_vc": {
              "type": "object",
              "properties": {
                "proof_type_values": {
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
                "proof_type_values",
                "cryptosuite"
              ],
              "additionalProperties": false
            },
            "di_vp": {
              "type": "object",
              "properties": {
                "proof_type_values": {
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
                "proof_type_values",
                "cryptosuite"
              ],
              "additionalProperties": false
            },
            "vc+sd-jwt": {
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
            "dc+sd-jwt": {
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
            "mso_mdoc": {
              "type": "object",
              "properties": {
                "issuerauth_alg_values": {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                "deviceauth_alg_values": {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                }
              },
              "additionalProperties": false
            }
          },
          "additionalProperties": false
        },
        "client_name": {
          "type": "string"
        },
        "logo_uri": {
          "type": "string"
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
    }
  }
};