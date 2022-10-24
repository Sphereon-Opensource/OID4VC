import nock from 'nock';

import { IssuanceInitiation, MetadataClient, WellKnownEndpoints } from '../lib';

describe('Metadataclient with IdentiProof Issuer should', () => {
  beforeAll(() => {
    nock.cleanAll();
  });
  it('succeed with OID4VCI and separate AS metadata', async () => {
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OIDC4VCI).reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA));

    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OAUTH_AS).reply(200, JSON.stringify(IDENTIPROOF_AS_METADATA));

    const metadata = await MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL);
    expect(metadata.credential_endpoint).toEqual('https://issuer.research.identiproof.io/credential');
    expect(metadata.token_endpoint).toEqual('https://auth.research.identiproof.io/oauth2/token');
    expect(metadata.oid4vci_metadata).toEqual(IDENTIPROOF_OID4VCI_METADATA);
  });

  it('succeed with OID4VCI and separate AS metadata from Initiation', async () => {
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OIDC4VCI).reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA));
    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OAUTH_AS).reply(200, JSON.stringify(IDENTIPROOF_AS_METADATA));

    const INITIATE_URI =
      'openid-initiate-issuance://?issuer=https%3A%2F%2Fissuer.research.identiproof.io&credential_type=OpenBadgeCredential&pre-authorized_code=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhOTUyZjUxNi1jYWVmLTQ4YjMtODIxYy00OTRkYzgyNjljZjAiLCJwcmUtYXV0aG9yaXplZCI6dHJ1ZX0.YE5DlalcLC2ChGEg47CQDaN1gTxbaQqSclIVqsSAUHE&user_pin_required=false';
    const initiation = IssuanceInitiation.fromURI(INITIATE_URI);
    const metadata = await MetadataClient.retrieveAllMetadataFromInitiation(initiation);
    expect(metadata.credential_endpoint).toEqual('https://issuer.research.identiproof.io/credential');
    expect(metadata.token_endpoint).toEqual('https://auth.research.identiproof.io/oauth2/token');
    expect(metadata.oid4vci_metadata).toEqual(IDENTIPROOF_OID4VCI_METADATA);
  });

  it('Fail without OID4VCI and only AS metadata (no credential endpoint)', async () => {
    nock(IDENTIPROOF_ISSUER_URL)
      .get(WellKnownEndpoints.OIDC4VCI)
      .reply(404, JSON.stringify({ error: 'does not exist' }));

    nock(IDENTIPROOF_ISSUER_URL)
      .get(WellKnownEndpoints.OIDC_CONFIGURATION)
      .reply(404, JSON.stringify({ error: 'does not exist' }));

    nock(IDENTIPROOF_ISSUER_URL)
      .get(WellKnownEndpoints.OAUTH_AS)
      .reply(404, JSON.stringify({ error: 'does not exist' }));

    await expect(() => MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL)).rejects.toThrowError(
      'Could not deduce the token endpoint for https://issuer.research.identiproof.io'
    );
  });

  it('Fail with OID4VCI and no AS metadata', async () => {
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OIDC4VCI).reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA));
    nock(IDENTIPROOF_ISSUER_URL)
      .get(WellKnownEndpoints.OIDC_CONFIGURATION)
      .reply(404, JSON.stringify({ error: 'does not exist' }));

    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OAUTH_AS).reply(404, JSON.stringify({}));
    await expect(() => MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL)).rejects.toThrowError(
      'URL https://auth.research.identiproof.io/.well-known/oauth-authorization-server was not found'
    );
  });
});

describe('Metadataclient with Spruce Issuer should', () => {
  it('succeed with OID4VCI and separate AS metadata', async () => {
    nock(SPRUCE_ISSUER_URL).get(WellKnownEndpoints.OIDC4VCI).reply(200, JSON.stringify(SPRUCE_OID4VCI_METADATA));

    const metadata = await MetadataClient.retrieveAllMetadata(SPRUCE_ISSUER_URL);
    expect(metadata.credential_endpoint).toEqual('https://ngi-oidc4vci-test.spruceid.xyz/credential');
    expect(metadata.token_endpoint).toEqual('https://ngi-oidc4vci-test.spruceid.xyz/token');
    expect(metadata.oid4vci_metadata).toEqual(SPRUCE_OID4VCI_METADATA);
  });

  it('Fail without OID4VCI', async () => {
    nock(SPRUCE_ISSUER_URL)
      .get(/.*/)
      .times(3)
      .reply(404, JSON.stringify({ error: 'does not exist' }));

    await expect(() => MetadataClient.retrieveAllMetadata(SPRUCE_ISSUER_URL)).rejects.toThrowError(
      'Could not deduce the token endpoint for https://ngi-oidc4vci-test.spruceid.xyz'
    );
  });
});

describe('Metadataclient with Danubetech should', () => {
  it('succeed without OID4VCI and with OIDC metadata', async () => {
    nock(DANUBE_ISSUER_URL).get(WellKnownEndpoints.OIDC_CONFIGURATION).reply(200, JSON.stringify(DANUBE_OIDC_METADATA));

    nock(DANUBE_ISSUER_URL)
      .get(/.well-known\/.*/)
      .times(2)
      .reply(404, JSON.stringify({ error: 'does not exist' }));
    const metadata = await MetadataClient.retrieveAllMetadata(DANUBE_ISSUER_URL);
    expect(metadata.credential_endpoint).toEqual('https://oidc4vc.uniissuer.io/credential');
    expect(metadata.token_endpoint).toEqual('https://oidc4vc.uniissuer.io/token');
    expect(metadata.oid4vci_metadata).toEqual(DANUBE_OIDC_METADATA);
  });

  it('Fail without OID4VCI', async () => {
    nock(SPRUCE_ISSUER_URL)
      .get(/.*/)
      .times(3)
      .reply(404, JSON.stringify({ error: 'does not exist' }));

    await expect(() => MetadataClient.retrieveAllMetadata(SPRUCE_ISSUER_URL)).rejects.toThrowError(
      'Could not deduce the token endpoint for https://ngi-oidc4vci-test.spruceid.xyz'
    );
  });
});

describe('Metadataclient with Walt-id should', () => {
  it('succeed without OID4VCI and with OIDC metadata', async () => {
    nock(WALT_ISSUER_URL).get(WellKnownEndpoints.OIDC4VCI).reply(200, JSON.stringify(WALT_OID4VCI_METADATA));

    nock(WALT_ISSUER_URL)
      .get(/.well-known\/.*/)
      .times(2)
      .reply(404, JSON.stringify({ error: 'does not exist' }));

    const metadata = await MetadataClient.retrieveAllMetadata(WALT_ISSUER_URL);
    expect(metadata.credential_endpoint).toEqual('https://issuer.walt-test.cloud/issuer-api/oidc/credential');
    expect(metadata.token_endpoint).toEqual('https://issuer.walt-test.cloud/issuer-api/oidc/token');
    expect(metadata.oid4vci_metadata).toEqual(WALT_OID4VCI_METADATA);
  });

  it('Fail without OID4VCI', async () => {
    nock(WALT_ISSUER_URL)
      .get(/.*/)
      .times(4)
      .reply(404, JSON.stringify({ error: 'does not exist' }));

    await expect(() => MetadataClient.retrieveAllMetadata(WALT_ISSUER_URL)).rejects.toThrowError(
      'Could not deduce the token endpoint for https://jff.walt.id/issuer-api/oidc'
    );
  });
});

const IDENTIPROOF_ISSUER_URL = 'https://issuer.research.identiproof.io';
const IDENTIPROOF_AS_URL = 'https://auth.research.identiproof.io';
const SPRUCE_ISSUER_URL = 'https://ngi-oidc4vci-test.spruceid.xyz';
const DANUBE_ISSUER_URL = 'https://oidc4vc.uniissuer.io';
const WALT_ISSUER_URL = 'https://jff.walt.id/issuer-api/oidc';
const IDENTIPROOF_AS_METADATA = {
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
const IDENTIPROOF_OID4VCI_METADATA = {
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

const SPRUCE_OID4VCI_METADATA = {
  issuer: 'https://ngi-oidc4vci-test.spruceid.xyz',
  credential_endpoint: 'https://ngi-oidc4vci-test.spruceid.xyz/credential',
  token_endpoint: 'https://ngi-oidc4vci-test.spruceid.xyz/token',
  jwks_uri: 'https://ngi-oidc4vci-test.spruceid.xyz/jwks',
  grant_types_supported: ['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
  credentials_supported: {
    OpenBadgeCredential: {
      formats: {
        jwt_vc: {
          types: [
            'https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential',
            'https://w3id.org/ngi/OpenBadgeExtendedCredential',
          ],
          binding_methods_supported: ['did'],
          cryptographic_suites_supported: ['ES256'],
        },
      },
    },
  },
};

const DANUBE_OIDC_METADATA = {
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

const WALT_OID4VCI_METADATA = {
  authorization_endpoint: 'https://issuer.walt-test.cloud/issuer-api/oidc/fulfillPAR',
  token_endpoint: 'https://issuer.walt-test.cloud/issuer-api/oidc/token',
  pushed_authorization_request_endpoint: 'https://issuer.walt-test.cloud/issuer-api/oidc/par',
  issuer: 'https://issuer.walt-test.cloud/issuer-api',
  jwks_uri: 'https://issuer.walt-test.cloud/issuer-api/oidc',
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
  credential_issuer: { display: [{ locale: null, name: 'https://issuer.walt-test.cloud/issuer-api' }] },
  credential_endpoint: 'https://issuer.walt-test.cloud/issuer-api/oidc/credential',
  subject_types_supported: ['public'],
};
