import { CredentialOfferClient } from '../CredentialOfferClient';

import { INITIATION_TEST, INITIATION_TEST_HTTPS_URI, INITIATION_TEST_URI } from './MetadataMocks';

describe('Issuance Initiation', () => {
  it('Should return Issuance Initiation Request with base URL from https URI', async () => {
    expect(await CredentialOfferClient.fromURI(INITIATION_TEST_HTTPS_URI)).toEqual({
      baseUrl: 'https://server.example.com',
      credential_offer: {
        credential_issuer: 'https://server.example.com',
        credentials: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
        grants: {
          authorization_code: {
            issuer_state: 'eyJhbGciOiJSU0Et...FYUaBy',
          },
        },
      },
      original_credential_offer: {
        credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
        issuer: 'https://server.example.com',
        op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
      },
      scheme: 'https',
      version: 1008,
    });
  });

  it('Should return Issuance Initiation Request with base URL from openid-initiate-issuance URI', async () => {
    expect(await CredentialOfferClient.fromURI(INITIATION_TEST_URI)).toEqual(INITIATION_TEST);
  });

  it('Should return Issuance Initiation URI from request', async () => {
    expect(await CredentialOfferClient.toURI(INITIATION_TEST)).toEqual(INITIATION_TEST_URI);
  });

  it('Should return URI from Issuance Initiation Request', async () => {
    const issuanceInitiationClient = await CredentialOfferClient.fromURI(INITIATION_TEST_HTTPS_URI);
    expect(await CredentialOfferClient.toURI(issuanceInitiationClient)).toEqual(INITIATION_TEST_HTTPS_URI);
  });

  it('Should throw error on invalid URI', async () => {
    const issuanceInitiationURI = INITIATION_TEST_HTTPS_URI.replace('?', '');
    await expect(async () => CredentialOfferClient.fromURI(issuanceInitiationURI)).rejects.toThrowError('Invalid Credential Offer Request');
  });
});
