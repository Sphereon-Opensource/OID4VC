import nock from 'nock';

import { WellKnownEndpoints } from '../lib';
import { MetadataClient } from '../lib/MetadataClient';

export const UNIT_TEST_TIMEOUT = 30000;


describe('Metadataclient should', () => {
  it(
    'succeed for IdentiProof with OID4VCI and separate AS metadata',
    async () => {
      nock(IDENTIPROOF_ISSUER_URL)
        .get(WellKnownEndpoints.OIDC4VCI)
        .reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA));

      nock(IDENTIPROOF_ISSUER_URL)
        .get(WellKnownEndpoints.OAUTH_AS)
        .reply(200, JSON.stringify(IDENTIPROOF_AS_METADATA));

      const metadata = await MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL);
      expect(metadata.credential_endpoint).toEqual('https://issuer.research.identiproof.io/credential');
      expect(metadata.token_endpoint).toEqual('https://auth.research.identiproof.io/oauth2/token');
      expect(metadata.oid4vci_metadata).toEqual(IDENTIPROOF_OID4VCI_METADATA)
    });
});




const IDENTIPROOF_ISSUER_URL = 'https://issuer.research.identiproof.io';
const IDENTIPROOF_AS_METADATA = {
  'issuer': 'https://auth.research.identiproof.io',
  'authorization_endpoint': 'https://auth.research.identiproof.io/oauth2/authorize',
  'token_endpoint': 'https://auth.research.identiproof.io/oauth2/token',
  'token_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt'],
  'jwks_uri': 'https://auth.research.identiproof.io/oauth2/jwks',
  'response_types_supported': ['code'],
  'grant_types_supported': ['authorization_code', 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'client_credentials', 'refresh_token'],
  'revocation_endpoint': 'https://auth.research.identiproof.io/oauth2/revoke',
  'revocation_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt'],
  'introspection_endpoint': 'https://auth.research.identiproof.io/oauth2/introspect',
  'introspection_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt'],
  'code_challenge_methods_supported': ['S256']
};
const IDENTIPROOF_OID4VCI_METADATA = {
  'issuer': 'https://issuer.research.identiproof.io',
  'auth_service': 'https://auth.research.identiproof.io',
  'credential_endpoint': 'https://issuer.research.identiproof.io/credential',
  'jwks_uri': 'https://issuer.research.identiproof.io/.well-known/did.json',
  'credentials_supported': {
    'Cyber Security Certificate': 'https://issuer.example.com#CyberSecurityCertificate',
    'OpenBadgeCredential': 'https://issuer.example.com#OpenBadgeCredential',
    'OpenBadgeExtendedCredential': 'https://issuer.example.com#OpenBadgeExtendedCredential'
  }
};
