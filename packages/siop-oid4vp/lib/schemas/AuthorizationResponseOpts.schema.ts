export const AuthorizationResponseOptsSchemaObj = {
  "$id": "AuthorizationResponseOptsSchema",
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$ref": "#/definitions/AuthorizationResponseOpts",
  "definitions": {
    "AuthorizationResponseOpts": {
      "type": "object",
      "properties": {
        "responseURI": {
          "type": "string"
        },
        "responseURIType": {
          "$ref": "#/definitions/ResponseURIType"
        },
        "registration": {
          "$ref": "#/definitions/ResponseRegistrationOpts"
        },
        "version": {
          "$ref": "#/definitions/SupportedVersion"
        },
        "audience": {
          "type": "string"
        },
        "createJwtCallback": {
          "$ref": "#/definitions/CreateJwtCallback"
        },
        "jwtIssuer": {
          "anyOf": [
            {
              "type": "object",
              "properties": {
                "method": {
                  "type": "string",
                  "const": "did"
                },
                "options": {
                  "type": "object",
                  "additionalProperties": {},
                  "description": "Additional options for the issuance context"
                },
                "didUrl": {
                  "type": "string"
                },
                "alg": {
                  "type": "string"
                }
              },
              "required": [
                "alg",
                "didUrl",
                "method"
              ],
              "additionalProperties": false
            },
            {
              "type": "object",
              "properties": {
                "method": {
                  "type": "string",
                  "const": "x5c"
                },
                "options": {
                  "type": "object",
                  "additionalProperties": {},
                  "description": "Additional options for the issuance context"
                },
                "alg": {
                  "type": "string"
                },
                "x5c": {
                  "type": "array",
                  "items": {
                    "type": "string"
                  },
                  "description": "Array of base64-encoded certificate strings in the DER-format.\n\nThe certificate containing the public key corresponding to the key used to digitally sign the JWS MUST be the first certificate."
                },
                "issuer": {
                  "type": "string",
                  "description": "The issuer jwt\n\nThis value will be used as the iss value of the issue jwt. It is also used as the client_id. And will also be set as the redirect_uri\n\nIt must match an entry in the x5c certificate leaf entry dnsName / uriName"
                }
              },
              "required": [
                "alg",
                "issuer",
                "method",
                "x5c"
              ],
              "additionalProperties": false
            },
            {
              "type": "object",
              "properties": {
                "method": {
                  "type": "string",
                  "const": "jwk"
                },
                "options": {
                  "type": "object",
                  "additionalProperties": {},
                  "description": "Additional options for the issuance context"
                },
                "alg": {
                  "type": "string"
                },
                "jwk": {
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
              },
              "required": [
                "alg",
                "jwk",
                "method"
              ],
              "additionalProperties": false
            },
            {
              "type": "object",
              "properties": {
                "method": {
                  "type": "string",
                  "const": "custom"
                },
                "options": {
                  "type": "object",
                  "additionalProperties": {},
                  "description": "Additional options for the issuance context"
                }
              },
              "required": [
                "method"
              ],
              "additionalProperties": false
            }
          ]
        },
        "responseMode": {
          "$ref": "#/definitions/ResponseMode"
        },
        "responseType": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/ResponseType"
          },
          "minItems": 1,
          "maxItems": 1
        },
        "expiresIn": {
          "type": "number"
        },
        "accessToken": {
          "type": "string"
        },
        "tokenType": {
          "type": "string"
        },
        "refreshToken": {
          "type": "string"
        },
        "presentationExchange": {
          "$ref": "#/definitions/PresentationExchangeResponseOpts"
        },
        "dcqlResponse": {
          "$ref": "#/definitions/DcqlResponseOpts"
        },
        "isFirstParty": {
          "type": "boolean"
        }
      },
      "required": [
        "createJwtCallback"
      ],
      "additionalProperties": false
    },
    "ResponseURIType": {
      "type": "string",
      "enum": [
        "response_uri",
        "redirect_uri"
      ]
    },
    "ResponseRegistrationOpts": {
      "anyOf": [
        {
          "type": "object",
          "properties": {
            "passBy": {
              "$ref": "#/definitions/PassBy"
            },
            "reference_uri": {
              "type": "string"
            },
            "targets": {
              "$ref": "#/definitions/PropertyTargets"
            },
            "id_token_encrypted_response_alg": {
              "$ref": "#/definitions/EncKeyAlgorithm"
            },
            "id_token_encrypted_response_enc": {
              "$ref": "#/definitions/EncSymmetricAlgorithmCode"
            },
            "authorizationEndpoint": {
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
            "responseTypesSupported": {
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
            "scopesSupported": {
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
            "subjectTypesSupported": {
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
            "idTokenSigningAlgValuesSupported": {
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
            "requestObjectSigningAlgValuesSupported": {
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
            "tokenEndpoint": {
              "type": "string"
            },
            "userinfoEndpoint": {
              "type": "string"
            },
            "jwksUri": {
              "type": "string"
            },
            "registrationEndpoint": {
              "type": "string"
            },
            "responseModesSupported": {
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
            "grantTypesSupported": {
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
            "acrValuesSupported": {
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
            "idTokenEncryptionAlgValuesSupported": {
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
            "idTokenEncryptionEncValuesSupported": {
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
            "userinfoSigningAlgValuesSupported": {
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
            "userinfoEncryptionAlgValuesSupported": {
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
            "userinfoEncryptionEncValuesSupported": {
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
            "requestObjectEncryptionAlgValuesSupported": {
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
            "requestObjectEncryptionEncValuesSupported": {
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
            "tokenEndpointAuthMethodsSupported": {
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
            "tokenEndpointAuthSigningAlgValuesSupported": {
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
            "displayValuesSupported": {
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
            "claimTypesSupported": {
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
              ]
            },
            "claimsSupported": {
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
            "serviceDocumentation": {
              "type": "string"
            },
            "claimsLocalesSupported": {
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
            "uiLocalesSupported": {
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
            "claimsParameterSupported": {
              "type": "boolean"
            },
            "requestParameterSupported": {
              "type": "boolean"
            },
            "requestUriParameterSupported": {
              "type": "boolean"
            },
            "requireRequestUriRegistration": {
              "type": "boolean"
            },
            "opPolicyUri": {
              "type": "string"
            },
            "opTosUri": {
              "type": "string"
            },
            "client_id": {
              "type": "string"
            },
            "redirectUris": {
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
            "clientName": {
              "type": "string"
            },
            "clientUri": {
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
            "tosUri": {
              "type": "string"
            },
            "policyUri": {
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
            "softwareId": {
              "type": "string"
            },
            "softwareVersion": {
              "type": "string"
            },
            "tokenEndpointAuthMethod": {
              "type": "string"
            },
            "applicationType": {
              "type": "string"
            },
            "responseTypes": {
              "type": "string"
            },
            "grantTypes": {
              "type": "string"
            },
            "vpFormats": {
              "$ref": "#/definitions/Format"
            },
            "logo_uri": {
              "type": "string"
            },
            "clientPurpose": {
              "type": "string"
            }
          },
          "required": [
            "passBy"
          ]
        },
        {
          "type": "object",
          "properties": {
            "passBy": {
              "$ref": "#/definitions/PassBy"
            },
            "reference_uri": {
              "type": "string"
            },
            "targets": {
              "$ref": "#/definitions/PropertyTargets"
            },
            "id_token_encrypted_response_alg": {
              "$ref": "#/definitions/EncKeyAlgorithm"
            },
            "id_token_encrypted_response_enc": {
              "$ref": "#/definitions/EncSymmetricAlgorithmCode"
            },
            "authorizationEndpoint": {
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
            "responseTypesSupported": {
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
            "scopesSupported": {
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
            "subjectTypesSupported": {
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
            "idTokenSigningAlgValuesSupported": {
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
            "requestObjectSigningAlgValuesSupported": {
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
            "tokenEndpoint": {
              "type": "string"
            },
            "userinfoEndpoint": {
              "type": "string"
            },
            "jwksUri": {
              "type": "string"
            },
            "registrationEndpoint": {
              "type": "string"
            },
            "responseModesSupported": {
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
            "grantTypesSupported": {
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
            "acrValuesSupported": {
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
            "idTokenEncryptionAlgValuesSupported": {
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
            "idTokenEncryptionEncValuesSupported": {
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
            "userinfoSigningAlgValuesSupported": {
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
            "userinfoEncryptionAlgValuesSupported": {
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
            "userinfoEncryptionEncValuesSupported": {
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
            "requestObjectEncryptionAlgValuesSupported": {
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
            "requestObjectEncryptionEncValuesSupported": {
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
            "tokenEndpointAuthMethodsSupported": {
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
            "tokenEndpointAuthSigningAlgValuesSupported": {
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
            "displayValuesSupported": {
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
            "claimTypesSupported": {
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
              ]
            },
            "claimsSupported": {
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
            "serviceDocumentation": {
              "type": "string"
            },
            "claimsLocalesSupported": {
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
            "uiLocalesSupported": {
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
            "claimsParameterSupported": {
              "type": "boolean"
            },
            "requestParameterSupported": {
              "type": "boolean"
            },
            "requestUriParameterSupported": {
              "type": "boolean"
            },
            "requireRequestUriRegistration": {
              "type": "boolean"
            },
            "opPolicyUri": {
              "type": "string"
            },
            "opTosUri": {
              "type": "string"
            },
            "client_id": {
              "type": "string"
            },
            "redirectUris": {
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
            "clientName": {
              "type": "string"
            },
            "clientUri": {
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
            "tosUri": {
              "type": "string"
            },
            "policyUri": {
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
            "softwareId": {
              "type": "string"
            },
            "softwareVersion": {
              "type": "string"
            },
            "tokenEndpointAuthMethod": {
              "type": "string"
            },
            "applicationType": {
              "type": "string"
            },
            "responseTypes": {
              "type": "string"
            },
            "grantTypes": {
              "type": "string"
            },
            "vpFormats": {
              "$ref": "#/definitions/Format"
            }
          },
          "required": [
            "passBy"
          ]
        },
        {
          "type": "object",
          "properties": {
            "passBy": {
              "$ref": "#/definitions/PassBy"
            },
            "reference_uri": {
              "type": "string"
            },
            "targets": {
              "$ref": "#/definitions/PropertyTargets"
            },
            "id_token_encrypted_response_alg": {
              "$ref": "#/definitions/EncKeyAlgorithm"
            },
            "id_token_encrypted_response_enc": {
              "$ref": "#/definitions/EncSymmetricAlgorithmCode"
            },
            "authorizationEndpoint": {
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
            "responseTypesSupported": {
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
            "scopesSupported": {
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
            "subjectTypesSupported": {
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
            "idTokenSigningAlgValuesSupported": {
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
            "requestObjectSigningAlgValuesSupported": {
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
            "tokenEndpoint": {
              "type": "string"
            },
            "userinfoEndpoint": {
              "type": "string"
            },
            "jwksUri": {
              "type": "string"
            },
            "registrationEndpoint": {
              "type": "string"
            },
            "responseModesSupported": {
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
            "grantTypesSupported": {
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
            "acrValuesSupported": {
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
            "idTokenEncryptionAlgValuesSupported": {
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
            "idTokenEncryptionEncValuesSupported": {
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
            "userinfoSigningAlgValuesSupported": {
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
            "userinfoEncryptionAlgValuesSupported": {
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
            "userinfoEncryptionEncValuesSupported": {
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
            "requestObjectEncryptionAlgValuesSupported": {
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
            "requestObjectEncryptionEncValuesSupported": {
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
            "tokenEndpointAuthMethodsSupported": {
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
            "tokenEndpointAuthSigningAlgValuesSupported": {
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
            "displayValuesSupported": {
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
            "claimTypesSupported": {
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
              ]
            },
            "claimsSupported": {
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
            "serviceDocumentation": {
              "type": "string"
            },
            "claimsLocalesSupported": {
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
            "uiLocalesSupported": {
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
            "claimsParameterSupported": {
              "type": "boolean"
            },
            "requestParameterSupported": {
              "type": "boolean"
            },
            "requestUriParameterSupported": {
              "type": "boolean"
            },
            "requireRequestUriRegistration": {
              "type": "boolean"
            },
            "opPolicyUri": {
              "type": "string"
            },
            "opTosUri": {
              "type": "string"
            },
            "idTokenTypesSupported": {
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
            "vpFormatsSupported": {
              "$ref": "#/definitions/Format"
            }
          },
          "required": [
            "passBy"
          ]
        }
      ]
    },
    "PassBy": {
      "type": "string",
      "enum": [
        "NONE",
        "REFERENCE",
        "VALUE"
      ]
    },
    "PropertyTargets": {
      "anyOf": [
        {
          "$ref": "#/definitions/PropertyTarget"
        },
        {
          "type": "array",
          "items": {
            "$ref": "#/definitions/PropertyTarget"
          }
        }
      ]
    },
    "PropertyTarget": {
      "type": "string",
      "enum": [
        "authorization-request",
        "request-object"
      ],
      "description": "Determines where a property will end up. Methods that support this argument are optional. If you do not provide any value it will default to all targets."
    },
    "EncKeyAlgorithm": {
      "type": "string",
      "const": "ECDH-ES"
    },
    "EncSymmetricAlgorithmCode": {
      "type": "string",
      "const": "XC20P"
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
        "fragment.jwt"
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
    "IdTokenType": {
      "type": "string",
      "enum": [
        "subject_signed",
        "attester_signed"
      ]
    },
    "SupportedVersion": {
      "type": "number",
      "enum": [
        70,
        110,
        180,
        200,
        71
      ]
    },
    "CreateJwtCallback": {
      "properties": {
        "isFunction": {
          "type": "boolean",
          "const": true
        }
      }
    },
    "PresentationExchangeResponseOpts": {
      "type": "object",
      "properties": {
        "verifiablePresentations": {
          "type": "array",
          "items": {
            "anyOf": [
              {
                "anyOf": [
                  {
                    "type": "object",
                    "properties": {
                      "proof": {
                        "anyOf": [
                          {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              },
                              "created": {
                                "type": "string"
                              },
                              "proofPurpose": {
                                "type": "string"
                              },
                              "verificationMethod": {
                                "type": "string"
                              },
                              "challenge": {
                                "type": "string"
                              },
                              "domain": {
                                "type": "string"
                              },
                              "proofValue": {
                                "type": "string"
                              },
                              "jws": {
                                "type": "string"
                              },
                              "jwt": {
                                "type": "string"
                              },
                              "mso_mdoc": {
                                "type": "string"
                              },
                              "nonce": {
                                "type": "string"
                              },
                              "requiredRevealStatements": {
                                "type": "array",
                                "items": {
                                  "type": "string"
                                }
                              }
                            },
                            "required": [
                              "type",
                              "created",
                              "proofPurpose",
                              "verificationMethod"
                            ]
                          },
                          {
                            "type": "array",
                            "items": {
                              "type": "object",
                              "properties": {
                                "type": {
                                  "type": "string"
                                },
                                "created": {
                                  "type": "string"
                                },
                                "proofPurpose": {
                                  "type": "string"
                                },
                                "verificationMethod": {
                                  "type": "string"
                                },
                                "challenge": {
                                  "type": "string"
                                },
                                "domain": {
                                  "type": "string"
                                },
                                "proofValue": {
                                  "type": "string"
                                },
                                "jws": {
                                  "type": "string"
                                },
                                "jwt": {
                                  "type": "string"
                                },
                                "mso_mdoc": {
                                  "type": "string"
                                },
                                "nonce": {
                                  "type": "string"
                                },
                                "requiredRevealStatements": {
                                  "type": "array",
                                  "items": {
                                    "type": "string"
                                  }
                                }
                              },
                              "required": [
                                "type",
                                "created",
                                "proofPurpose",
                                "verificationMethod"
                              ]
                            }
                          }
                        ]
                      },
                      "id": {
                        "type": "string"
                      },
                      "@context": {
                        "anyOf": [
                          {
                            "type": "object",
                            "properties": {
                              "name": {
                                "type": "string"
                              },
                              "did": {
                                "type": "string"
                              }
                            }
                          },
                          {
                            "type": "string"
                          },
                          {
                            "type": "array",
                            "items": {
                              "anyOf": [
                                {
                                  "type": "object",
                                  "properties": {
                                    "name": {
                                      "type": "string"
                                    },
                                    "did": {
                                      "type": "string"
                                    }
                                  }
                                },
                                {
                                  "type": "string"
                                }
                              ]
                            }
                          }
                        ]
                      },
                      "type": {
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
                      "verifiableCredential": {
                        "type": "array",
                        "items": {
                          "anyOf": [
                            {
                              "type": "object",
                              "properties": {
                                "proof": {
                                  "anyOf": [
                                    {
                                      "type": "object",
                                      "properties": {
                                        "type": {
                                          "type": "string"
                                        },
                                        "created": {
                                          "type": "string"
                                        },
                                        "proofPurpose": {
                                          "type": "string"
                                        },
                                        "verificationMethod": {
                                          "type": "string"
                                        },
                                        "challenge": {
                                          "type": "string"
                                        },
                                        "domain": {
                                          "type": "string"
                                        },
                                        "proofValue": {
                                          "type": "string"
                                        },
                                        "jws": {
                                          "type": "string"
                                        },
                                        "jwt": {
                                          "type": "string"
                                        },
                                        "mso_mdoc": {
                                          "type": "string"
                                        },
                                        "nonce": {
                                          "type": "string"
                                        },
                                        "requiredRevealStatements": {
                                          "type": "array",
                                          "items": {
                                            "type": "string"
                                          }
                                        }
                                      },
                                      "required": [
                                        "type",
                                        "created",
                                        "proofPurpose",
                                        "verificationMethod"
                                      ]
                                    },
                                    {
                                      "type": "array",
                                      "items": {
                                        "type": "object",
                                        "properties": {
                                          "type": {
                                            "type": "string"
                                          },
                                          "created": {
                                            "type": "string"
                                          },
                                          "proofPurpose": {
                                            "type": "string"
                                          },
                                          "verificationMethod": {
                                            "type": "string"
                                          },
                                          "challenge": {
                                            "type": "string"
                                          },
                                          "domain": {
                                            "type": "string"
                                          },
                                          "proofValue": {
                                            "type": "string"
                                          },
                                          "jws": {
                                            "type": "string"
                                          },
                                          "jwt": {
                                            "type": "string"
                                          },
                                          "mso_mdoc": {
                                            "type": "string"
                                          },
                                          "nonce": {
                                            "type": "string"
                                          },
                                          "requiredRevealStatements": {
                                            "type": "array",
                                            "items": {
                                              "type": "string"
                                            }
                                          }
                                        },
                                        "required": [
                                          "type",
                                          "created",
                                          "proofPurpose",
                                          "verificationMethod"
                                        ]
                                      }
                                    }
                                  ]
                                },
                                "@context": {
                                  "anyOf": [
                                    {
                                      "type": "object",
                                      "properties": {
                                        "name": {
                                          "type": "string"
                                        },
                                        "did": {
                                          "type": "string"
                                        }
                                      }
                                    },
                                    {
                                      "type": "string"
                                    },
                                    {
                                      "type": "array",
                                      "items": {
                                        "anyOf": [
                                          {
                                            "type": "object",
                                            "properties": {
                                              "name": {
                                                "type": "string"
                                              },
                                              "did": {
                                                "type": "string"
                                              }
                                            }
                                          },
                                          {
                                            "type": "string"
                                          }
                                        ]
                                      }
                                    }
                                  ]
                                },
                                "type": {
                                  "type": "array",
                                  "items": {
                                    "type": "string"
                                  }
                                },
                                "credentialSchema": {
                                  "anyOf": [
                                    {
                                      "type": "object",
                                      "properties": {
                                        "id": {
                                          "type": "string"
                                        },
                                        "type": {
                                          "type": "string"
                                        }
                                      },
                                      "required": [
                                        "id"
                                      ],
                                      "additionalProperties": false
                                    },
                                    {
                                      "type": "string"
                                    },
                                    {
                                      "type": "array",
                                      "items": {
                                        "anyOf": [
                                          {
                                            "type": "object",
                                            "properties": {
                                              "id": {
                                                "type": "string"
                                              },
                                              "type": {
                                                "type": "string"
                                              }
                                            },
                                            "required": [
                                              "id"
                                            ],
                                            "additionalProperties": false
                                          },
                                          {
                                            "type": "string"
                                          }
                                        ]
                                      }
                                    }
                                  ]
                                },
                                "issuer": {
                                  "anyOf": [
                                    {
                                      "type": "string"
                                    },
                                    {
                                      "type": "object",
                                      "properties": {
                                        "id": {
                                          "type": "string"
                                        }
                                      },
                                      "required": [
                                        "id"
                                      ]
                                    }
                                  ]
                                },
                                "issuanceDate": {
                                  "type": "string"
                                },
                                "credentialSubject": {
                                  "anyOf": [
                                    {
                                      "type": "object",
                                      "properties": {
                                        "id": {
                                          "type": "string"
                                        }
                                      }
                                    },
                                    {
                                      "type": "array",
                                      "items": {
                                        "type": "object",
                                        "properties": {
                                          "id": {
                                            "type": "string"
                                          }
                                        }
                                      }
                                    }
                                  ]
                                },
                                "expirationDate": {
                                  "type": "string"
                                },
                                "id": {
                                  "type": "string"
                                },
                                "credentialStatus": {
                                  "type": "object",
                                  "properties": {
                                    "id": {
                                      "type": "string"
                                    },
                                    "type": {
                                      "type": "string"
                                    }
                                  },
                                  "required": [
                                    "id",
                                    "type"
                                  ]
                                },
                                "description": {
                                  "type": "string"
                                },
                                "name": {
                                  "type": "string"
                                }
                              },
                              "required": [
                                "@context",
                                "credentialSubject",
                                "issuanceDate",
                                "issuer",
                                "proof",
                                "type"
                              ]
                            },
                            {
                              "type": "string",
                              "description": "Represents a Json Web Token in compact form."
                            }
                          ],
                          "description": "Represents a signed Verifiable Credential (includes proof), in either JSON, compact JWT or compact SD-JWT VC format. See  {@link  https://www.w3.org/TR/vc-data-model/#credentials VC data model }  See  {@link  https://www.w3.org/TR/vc-data-model/#proof-formats proof formats }"
                        }
                      },
                      "presentation_submission": {
                        "type": "object",
                        "properties": {
                          "id": {
                            "type": "string",
                            "description": "A UUID or some other unique ID to identify this Presentation Submission"
                          },
                          "definition_id": {
                            "type": "string",
                            "description": "A UUID or some other unique ID to identify this Presentation Definition"
                          },
                          "descriptor_map": {
                            "type": "array",
                            "items": {
                              "type": "object",
                              "properties": {
                                "id": {
                                  "type": "string",
                                  "description": "ID to identify the descriptor from Presentation Definition Input Descriptor it coresponds to."
                                },
                                "path": {
                                  "type": "string",
                                  "description": "The path where the verifiable credential is located in the presentation submission json"
                                },
                                "path_nested": {
                                  "$ref": "#/definitions/interface-2011259945-6983-7473-2011259945-0-610221317389438"
                                },
                                "format": {
                                  "type": "string",
                                  "description": "The Proof or JWT algorith that the proof is in"
                                }
                              },
                              "required": [
                                "id",
                                "path",
                                "format"
                              ],
                              "additionalProperties": false,
                              "description": "descriptor map laying out the structure of the presentation submission."
                            },
                            "description": "List of descriptors of how the claims are being mapped to presentation definition"
                          }
                        },
                        "required": [
                          "id",
                          "definition_id",
                          "descriptor_map"
                        ],
                        "additionalProperties": false,
                        "description": "It expresses how the inputs are presented as proofs to a Verifier."
                      },
                      "holder": {
                        "type": "string"
                      },
                      "verifier": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "@context",
                      "proof"
                    ]
                  },
                  {
                    "type": "string",
                    "description": "Represents a Json Web Token in compact form."
                  }
                ],
                "description": "Represents a signed Verifiable Presentation (includes proof), in either JSON or compact JWT format. See  {@link  https://www.w3.org/TR/vc-data-model/#presentations VC data model }  See  {@link  https://www.w3.org/TR/vc-data-model/#proof-formats proof formats }"
              },
              {
                "type": "string",
                "description": "Represents a selective disclosure JWT vc in compact form."
              },
              {
                "type": "string"
              }
            ]
          }
        },
        "vpTokenLocation": {
          "$ref": "#/definitions/VPTokenLocation"
        },
        "presentationSubmission": {
          "type": "object",
          "properties": {
            "id": {
              "type": "string",
              "description": "A UUID or some other unique ID to identify this Presentation Submission"
            },
            "definition_id": {
              "type": "string",
              "description": "A UUID or some other unique ID to identify this Presentation Definition"
            },
            "descriptor_map": {
              "type": "array",
              "items": {
                "type": "object",
                "properties": {
                  "id": {
                    "type": "string",
                    "description": "ID to identify the descriptor from Presentation Definition Input Descriptor it coresponds to."
                  },
                  "path": {
                    "type": "string",
                    "description": "The path where the verifiable credential is located in the presentation submission json"
                  },
                  "path_nested": {
                    "$ref": "#/definitions/interface-2011259945-6983-7473-2011259945-0-610221317389438"
                  },
                  "format": {
                    "type": "string",
                    "description": "The Proof or JWT algorith that the proof is in"
                  }
                },
                "required": [
                  "id",
                  "path",
                  "format"
                ],
                "additionalProperties": false,
                "description": "descriptor map laying out the structure of the presentation submission."
              },
              "description": "List of descriptors of how the claims are being mapped to presentation definition"
            }
          },
          "required": [
            "id",
            "definition_id",
            "descriptor_map"
          ],
          "additionalProperties": false,
          "description": "It expresses how the inputs are presented as proofs to a Verifier."
        },
        "restrictToFormats": {
          "$ref": "#/definitions/Format"
        },
        "restrictToDIDMethods": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "verifiablePresentations"
      ],
      "additionalProperties": false
    },
    "interface-2011259945-6983-7473-2011259945-0-610221317389438": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string",
          "description": "ID to identify the descriptor from Presentation Definition Input Descriptor it coresponds to."
        },
        "path": {
          "type": "string",
          "description": "The path where the verifiable credential is located in the presentation submission json"
        },
        "path_nested": {
          "$ref": "#/definitions/interface-2011259945-6983-7473-2011259945-0-610221317389438"
        },
        "format": {
          "type": "string",
          "description": "The Proof or JWT algorith that the proof is in"
        }
      },
      "required": [
        "id",
        "path",
        "format"
      ],
      "additionalProperties": false,
      "description": "descriptor map laying out the structure of the presentation submission."
    },
    "VPTokenLocation": {
      "type": "string",
      "enum": [
        "authorization_response",
        "id_token",
        "token_response"
      ]
    },
    "DcqlResponseOpts": {
      "type": "object",
      "properties": {
        "dcqlPresentation": {
          "type": "object",
          "additionalProperties": {
            "anyOf": [
              {
                "type": "object",
                "additionalProperties": {}
              },
              {
                "type": "string"
              }
            ]
          }
        }
      },
      "required": [
        "dcqlPresentation"
      ],
      "additionalProperties": false
    }
  }
};