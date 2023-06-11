import { AuthzFlowType, CredentialOfferRequestWithBaseUrl } from '@sphereon/oid4vci-common';

export const IDENTIPROOF_ISSUER_URL = 'https://issuer.research.identiproof.io';
export const IDENTIPROOF_AS_URL = 'https://auth.research.identiproof.io';
export const SPRUCE_ISSUER_URL = 'https://ngi-oidc4vci-test.spruceid.xyz';
export const DANUBE_ISSUER_URL = 'https://oidc4vc.uniissuer.io';
export const WALT_ISSUER_URL = 'https://jff.walt.id/issuer-api/oidc';
export const INITIATION_TEST_HTTPS_URI =
  'https://server.example.com?issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy';
export const INITIATION_TEST_URI =
  'openid-initiate-issuance://?credential_type=OpenBadgeCredential&issuer=https%3A%2F%2Fjff%2Ewalt%2Eid%2Fissuer-api%2Foidc%2F&pre-authorized_code=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhOTUyZjUxNi1jYWVmLTQ4YjMtODIxYy00OTRkYzgyNjljZjAiLCJwcmUtYXV0aG9yaXplZCI6dHJ1ZX0.YE5DlalcLC2ChGEg47CQDaN1gTxbaQqSclIVqsSAUHE&user_pin_required=false';

export const INITIATION_TEST: CredentialOfferRequestWithBaseUrl = {
  baseUrl: 'openid-initiate-issuance://',
  credential_offer: {
    credential_issuer: 'https://jff.walt.id/issuer-api/oidc/',
    credentials: ['OpenBadgeCredential'],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code':
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhOTUyZjUxNi1jYWVmLTQ4YjMtODIxYy00OTRkYzgyNjljZjAiLCJwcmUtYXV0aG9yaXplZCI6dHJ1ZX0.YE5DlalcLC2ChGEg47CQDaN1gTxbaQqSclIVqsSAUHE',
        user_pin_required: false,
      },
    },
  },
  original_credential_offer: {
    credential_type: ['OpenBadgeCredential'],
    issuer: 'https://jff.walt.id/issuer-api/oidc/',
    'pre-authorized_code':
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhOTUyZjUxNi1jYWVmLTQ4YjMtODIxYy00OTRkYzgyNjljZjAiLCJwcmUtYXV0aG9yaXplZCI6dHJ1ZX0.YE5DlalcLC2ChGEg47CQDaN1gTxbaQqSclIVqsSAUHE',
    user_pin_required: 'false',
  },
  preAuthorizedCode:
    'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhOTUyZjUxNi1jYWVmLTQ4YjMtODIxYy00OTRkYzgyNjljZjAiLCJwcmUtYXV0aG9yaXplZCI6dHJ1ZX0.YE5DlalcLC2ChGEg47CQDaN1gTxbaQqSclIVqsSAUHE',
  scheme: 'openid-initiate-issuance',
  supportedFlows: [AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW],
  userPinRequired: false,
  version: 1008,
};
export const IDENTIPROOF_AS_METADATA = {
  issuer: 'https://auth.research.identiproof.io',
  authorization_endpoint: 'https://auth.research.identiproof.io/oauth2/authorize',
  token_endpoint: 'https://auth.research.identiproof.io/oauth2/token',
  token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt'],
  jwks_uri: 'https://auth.research.identiproof.io/oauth2/jwks',
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code', 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'client_credentials', 'refresh_token'],
  revocation_endpoint: 'https://auth.research.identiproof.io/oauth2/revoke',
  revocation_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt'],
  introspection_endpoint: 'https://auth.research.identiproof.io/oauth2/introspect',
  introspection_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt'],
  code_challenge_methods_supported: ['S256'],
};

export const IDENTIPROOF_OID4VCI_METADATA = {
  issuer: 'https://issuer.research.identiproof.io',
  authorization_server: 'https://auth.research.identiproof.io',
  credential_endpoint: 'https://issuer.research.identiproof.io/credential',
  jwks_uri: 'https://issuer.research.identiproof.io/.well-known/did.json',
  credentials_supported: {
    'Cyber Security Certificate': {
      formats: {
        jwt_vc: {
          types: ['VerifiableCredential', 'Cyber Security Certificate'],
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['ES256'],
        },
      },
    },
    OpenBadgeCredential: {
      formats: {
        jwt_vc: {
          types: ['VerifiableCredential', 'OpenBadgeCredential'],
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['ES256'],
        },
      },
    },
    OpenBadgeExtendedCredential: {
      formats: {
        jwt_vc: {
          types: ['VerifiableCredential', 'OpenBadgeExtendedCredential'],
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['ES256'],
        },
      },
    },
  },
};

export const SPRUCE_OID4VCI_METADATA = {
  issuer: 'https://ngi-oidc4vci-test.spruceid.xyz',
  credential_endpoint: 'https://ngi-oidc4vci-test.spruceid.xyz/credential',
  token_endpoint: 'https://ngi-oidc4vci-test.spruceid.xyz/token',
  jwks_uri: 'https://ngi-oidc4vci-test.spruceid.xyz/jwks',
  grant_types_supported: ['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
  credentials_supported: {
    OpenBadgeCredential: {
      formats: {
        jwt_vc: {
          types: ['VerifiableCredential', 'OpenBadgeCredential'],
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['ES256', 'ES256K'],
        },
        ldp_vc: {
          types: ['VerifiableCredential', 'OpenBadgeCredential'],
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['Ed25519Signature2018'],
        },
      },
    },
  },
};

export const DANUBE_OIDC_METADATA = {
  response_types_supported: ['code', 'token'],
  credentials_supported: {
    OpenBadgeCredential: {
      display: [
        {
          name: 'Open Badge V3',
          locale: 'en-US',
          logo: { url: 'https://uniissuer.io/images/logo.jpg' },
        },
      ],
      formats: {
        ldp_vc: {
          types: ['VerifiableCredential', 'OpenBadgeCredential'],
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['Ed25519Signature2018', 'Ed25519Signature2020', 'EcdsaSecp256k1Signature2019', 'JsonWebSignature2020'],
        },
        jwt_vc: {
          types: ['VerifiableCredential', 'OpenBadgeCredential'],
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['Ed25519Signature2018', 'Ed25519Signature2020', 'EcdsaSecp256k1Signature2019', 'JsonWebSignature2020'],
        },
      },
      claims: { achievement: { mandatory: true, value_type: 'object' } },
    },
    VaccinationCertificate: {
      formats: {
        jwt_vc: {
          types: ['VerifiableCredential', 'VaccinationCertificate'],
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['Ed25519Signature2018', 'Ed25519Signature2020', 'EcdsaSecp256k1Signature2019', 'JsonWebSignature2020'],
        },
      },
    },
  },
  credential_issuer: {
    display: [
      {
        name: 'Danube Tech',
        locale: 'en-US',
        logo: { url: 'https://uniissuer.io/images/logo.jpg' },
      },
    ],
  },
  code_challenge_methods_supported: ['plain', 'S256'],
  grant_types_supported: ['authorization_code', 'urn:ietf:params:oauth:grant-type:pre-authorized_code'],
  token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
  authorization_endpoint: 'https://oidc4vc.uniissuer.io/authorize',
  token_endpoint: 'https://oidc4vc.uniissuer.io/token',
  credential_endpoint: 'https://oidc4vc.uniissuer.io/credential',
};

export const WALT_OID4VCI_METADATA = {
  authorization_endpoint: 'https://jff.walt.id/issuer-api/oidc/fulfillPAR',
  token_endpoint: 'https://jff.walt.id/issuer-api/oidc/token',
  pushed_authorization_request_endpoint: 'https://jff.walt.id/issuer-api/oidc/par',
  issuer: 'https://jff.walt.id/issuer-api',
  jwks_uri: 'https://jff.walt.id/issuer-api/oidc',
  grant_types_supported: ['authorization_code', 'urn:ietf:params:oauth:grant-type:pre-authorized_code'],
  request_uri_parameter_supported: true,
  credentials_supported: {
    VerifiableDiploma: {
      display: [{ name: 'VerifiableDiploma' }],
      formats: {
        ldp_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: [
            'Ed25519Signature2018',
            'Ed25519Signature2020',
            'EcdsaSecp256k1Signature2019',
            'RsaSignature2018',
            'JsonWebSignature2020',
            'JcsEd25519Signature2020',
          ],
          types: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableDiploma'],
        },
        jwt_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
          types: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableDiploma'],
        },
      },
    },
    VerifiableVaccinationCertificate: {
      display: [{ name: 'VerifiableVaccinationCertificate' }],
      formats: {
        ldp_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: [
            'Ed25519Signature2018',
            'Ed25519Signature2020',
            'EcdsaSecp256k1Signature2019',
            'RsaSignature2018',
            'JsonWebSignature2020',
            'JcsEd25519Signature2020',
          ],
          types: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableVaccinationCertificate'],
        },
        jwt_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
          types: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableVaccinationCertificate'],
        },
      },
    },
    Europass: {
      display: [{ name: 'Europass' }],
      formats: {
        ldp_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: [
            'Ed25519Signature2018',
            'Ed25519Signature2020',
            'EcdsaSecp256k1Signature2019',
            'RsaSignature2018',
            'JsonWebSignature2020',
            'JcsEd25519Signature2020',
          ],
          types: ['VerifiableCredential', 'VerifiableAttestation', 'Europass'],
        },
        jwt_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
          types: ['VerifiableCredential', 'VerifiableAttestation', 'Europass'],
        },
      },
    },
    VerifiableMandate: {
      display: [{ name: 'VerifiableMandate' }],
      formats: {
        ldp_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: [
            'Ed25519Signature2018',
            'Ed25519Signature2020',
            'EcdsaSecp256k1Signature2019',
            'RsaSignature2018',
            'JsonWebSignature2020',
            'JcsEd25519Signature2020',
          ],
          types: ['VerifiableCredential', 'VerifiableMandate'],
        },
        jwt_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
          types: ['VerifiableCredential', 'VerifiableMandate'],
        },
      },
    },
    EuropeanBankIdentity: {
      display: [{ name: 'EuropeanBankIdentity' }],
      formats: {
        ldp_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: [
            'Ed25519Signature2018',
            'Ed25519Signature2020',
            'EcdsaSecp256k1Signature2019',
            'RsaSignature2018',
            'JsonWebSignature2020',
            'JcsEd25519Signature2020',
          ],
          types: ['VerifiableCredential', 'EuropeanBankIdentity'],
        },
        jwt_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
          types: ['VerifiableCredential', 'EuropeanBankIdentity'],
        },
      },
    },
    VerifiableAttestation: {
      display: [{ name: 'VerifiableAttestation' }],
      formats: {
        ldp_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: [
            'Ed25519Signature2018',
            'Ed25519Signature2020',
            'EcdsaSecp256k1Signature2019',
            'RsaSignature2018',
            'JsonWebSignature2020',
            'JcsEd25519Signature2020',
          ],
          types: ['VerifiableCredential', 'VerifiableAttestation'],
        },
        jwt_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
          types: ['VerifiableCredential', 'VerifiableAttestation'],
        },
      },
    },
    OpenBadgeCredential: {
      display: [{ name: 'OpenBadgeCredential' }],
      formats: {
        ldp_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: [
            'Ed25519Signature2018',
            'Ed25519Signature2020',
            'EcdsaSecp256k1Signature2019',
            'RsaSignature2018',
            'JsonWebSignature2020',
            'JcsEd25519Signature2020',
          ],
          types: ['VerifiableCredential', 'OpenBadgeCredential'],
        },
        jwt_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
          types: ['VerifiableCredential', 'OpenBadgeCredential'],
        },
      },
    },
    PeerReview: {
      display: [{ name: 'PeerReview' }],
      formats: {
        ldp_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: [
            'Ed25519Signature2018',
            'Ed25519Signature2020',
            'EcdsaSecp256k1Signature2019',
            'RsaSignature2018',
            'JsonWebSignature2020',
            'JcsEd25519Signature2020',
          ],
          types: ['VerifiableCredential', 'PeerReview'],
        },
        jwt_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
          types: ['VerifiableCredential', 'PeerReview'],
        },
      },
    },
    ProofOfResidence: {
      display: [{ name: 'ProofOfResidence' }],
      formats: {
        ldp_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: [
            'Ed25519Signature2018',
            'Ed25519Signature2020',
            'EcdsaSecp256k1Signature2019',
            'RsaSignature2018',
            'JsonWebSignature2020',
            'JcsEd25519Signature2020',
          ],
          types: ['VerifiableCredential', 'VerifiableAttestation', 'ProofOfResidence'],
        },
        jwt_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
          types: ['VerifiableCredential', 'VerifiableAttestation', 'ProofOfResidence'],
        },
      },
    },
    AmletCredential: {
      display: [{ name: 'AmletCredential' }],
      formats: {
        ldp_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: [
            'Ed25519Signature2018',
            'Ed25519Signature2020',
            'EcdsaSecp256k1Signature2019',
            'RsaSignature2018',
            'JsonWebSignature2020',
            'JcsEd25519Signature2020',
          ],
          types: ['VerifiableCredential', 'AmletCredential'],
        },
        jwt_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
          types: ['VerifiableCredential', 'AmletCredential'],
        },
      },
    },
    ParticipantCredential: {
      display: [{ name: 'ParticipantCredential' }],
      formats: {
        ldp_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: [
            'Ed25519Signature2018',
            'Ed25519Signature2020',
            'EcdsaSecp256k1Signature2019',
            'RsaSignature2018',
            'JsonWebSignature2020',
            'JcsEd25519Signature2020',
          ],
          types: ['VerifiableCredential', 'ParticipantCredential'],
        },
        jwt_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
          types: ['VerifiableCredential', 'ParticipantCredential'],
        },
      },
    },
    VerifiableId: {
      display: [{ name: 'VerifiableId' }],
      formats: {
        ldp_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: [
            'Ed25519Signature2018',
            'Ed25519Signature2020',
            'EcdsaSecp256k1Signature2019',
            'RsaSignature2018',
            'JsonWebSignature2020',
            'JcsEd25519Signature2020',
          ],
          types: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableId'],
        },
        jwt_vc: {
          cryptographic_binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
          types: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableId'],
        },
      },
    },
  },
  credential_issuer: { display: [{ locale: null, name: 'https://jff.walt.id/issuer-api' }] },
  credential_endpoint: 'https://jff.walt.id/issuer-api/oidc/credential',
  subject_types_supported: ['public'],
};
