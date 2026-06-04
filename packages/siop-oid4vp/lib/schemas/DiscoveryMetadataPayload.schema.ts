export const DiscoveryMetadataPayloadSchemaObj = {
  "$id": "DiscoveryMetadataPayloadSchema",
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$ref": "#/definitions/DiscoveryMetadataPayload",
  "definitions": {
    "DiscoveryMetadataPayload": {
      "type": "object",
      "properties": {
        "authorization_endpoint": {
          "anyOf": [
            {
              "$ref": "#/definitions/Schema"
            },
            {
              "type": "string"
            }
          ]
        },
        "issuer": {
          "anyOf": [
            {
              "$ref": "#/definitions/ResponseIss"
            },
            {
              "type": "string"
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
        "subject_syntax_types_supported": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "token_endpoint": {
          "type": "string"
        },
        "userinfo_endpoint": {
          "type": "string"
        },
        "jwks_uri": {
          "type": "string"
        },
        "registration_endpoint": {
          "type": "string"
        },
        "response_modes_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/ResponseMode"
              }
            },
            {
              "$ref": "#/definitions/ResponseMode"
            }
          ]
        },
        "grant_types_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/GrantType"
              }
            },
            {
              "$ref": "#/definitions/GrantType"
            }
          ]
        },
        "acr_values_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/AuthenticationContextReferences"
              }
            },
            {
              "$ref": "#/definitions/AuthenticationContextReferences"
            }
          ]
        },
        "id_token_encryption_alg_values_supported": {
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
        "id_token_encryption_enc_values_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "type": "string"
              }
            },
            {
              "type": "string"
            }
          ],
          "description": "OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT]."
        },
        "userinfo_signing_alg_values_supported": {
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
        "userinfo_encryption_alg_values_supported": {
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
        "userinfo_encryption_enc_values_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "type": "string"
              }
            },
            {
              "type": "string"
            }
          ],
          "description": "OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT]."
        },
        "request_object_encryption_alg_values_supported": {
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
        "request_object_encryption_enc_values_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "type": "string"
              }
            },
            {
              "type": "string"
            }
          ],
          "description": "OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for Request Objects. These algorithms are used both when the Request Object is passed by value and when it is passed by reference."
        },
        "token_endpoint_auth_methods_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/TokenEndpointAuthMethod"
              }
            },
            {
              "$ref": "#/definitions/TokenEndpointAuthMethod"
            }
          ]
        },
        "token_endpoint_auth_signing_alg_values_supported": {
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
        "display_values_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {}
            },
            {}
          ],
          "description": "OPTIONAL. JSON array containing a list of the display parameter values that the OpenID Provider supports. These values are described in Section 3.1.2.1 of OpenID Connect Core 1.0 [OpenID.Core]."
        },
        "claim_types_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/ClaimType"
              }
            },
            {
              "$ref": "#/definitions/ClaimType"
            }
          ],
          "description": "OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports. These Claim Types are described in Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core]. Values defined by this specification are normal, aggregated, and distributed. If omitted, the implementation supports only normal Claims."
        },
        "claims_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "type": "string"
              }
            },
            {
              "type": "string"
            }
          ],
          "description": "RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for. Note that for privacy or other reasons, this might not be an exhaustive list."
        },
        "service_documentation": {
          "type": "string"
        },
        "claims_locales_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "type": "string"
              }
            },
            {
              "type": "string"
            }
          ]
        },
        "ui_locales_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "type": "string"
              }
            },
            {
              "type": "string"
            }
          ]
        },
        "claims_parameter_supported": {
          "type": "boolean"
        },
        "request_parameter_supported": {
          "type": "boolean"
        },
        "request_uri_parameter_supported": {
          "type": "boolean"
        },
        "require_request_uri_registration": {
          "type": "boolean"
        },
        "op_policy_uri": {
          "type": "string"
        },
        "op_tos_uri": {
          "type": "string"
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
        "jwks": {
          "type": "object",
          "properties": {
            "keys": {
              "type": "array",
              "items": {
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
              }
            }
          },
          "required": [
            "keys"
          ],
          "additionalProperties": false
        },
        "software_id": {
          "type": "string"
        },
        "software_version": {
          "type": "string"
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
                    "type": "number"
                  }
                },
                "deviceauth_alg_values": {
                  "type": "array",
                  "items": {
                    "type": "number"
                  }
                }
              },
              "additionalProperties": false
            }
          },
          "additionalProperties": false
        },
        "id_token_types_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/IdTokenType"
              }
            },
            {
              "$ref": "#/definitions/IdTokenType"
            }
          ]
        },
        "encrypted_response_enc_values_supported": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "client_id_prefixes_supported": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      }
    },
    "Schema": {
      "type": "string",
      "enum": [
        "openid:",
        "openid-vc:"
      ]
    },
    "ResponseIss": {
      "type": "string",
      "enum": [
        "https://self-issued.me",
        "https://self-issued.me/v2",
        "https://self-issued.me/v2/openid-vc"
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
        "fragment.jwt",
        "dc_api",
        "dc_api.jwt"
      ]
    },
    "GrantType": {
      "type": "string",
      "enum": [
        "authorization_code",
        "implicit"
      ]
    },
    "AuthenticationContextReferences": {
      "type": "string",
      "enum": [
        "phr",
        "phrh"
      ]
    },
    "TokenEndpointAuthMethod": {
      "type": "string",
      "enum": [
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt"
      ]
    },
    "ClaimType": {
      "type": "string",
      "enum": [
        "normal",
        "aggregated",
        "distributed"
      ]
    },
    "IdTokenType": {
      "type": "string",
      "enum": [
        "subject_signed",
        "attester_signed"
      ]
    }
  }
};