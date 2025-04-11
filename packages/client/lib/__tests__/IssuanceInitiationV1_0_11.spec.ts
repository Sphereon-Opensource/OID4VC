import { OpenId4VCIVersion } from '@sphereon/oid4vci-common';
import { describe, expect, it } from 'vitest';

import { CredentialOfferClient } from '../CredentialOfferClient';
import { CredentialOfferClientV1_0_11 } from '../CredentialOfferClientV1_0_11';

import { INITIATION_TEST_HTTPS_URI, INITIATION_TEST_HTTPS_URI_V1_0_11, INITIATION_TEST_URI_V1_0_08, INITIATION_TEST_V1_0_08 } from './MetadataMocks';

describe('Issuance Initiation V1_0_11', () => {
  it('Should return Issuance Initiation Request with base URL from https URI', async () => {
    expect(await CredentialOfferClientV1_0_11.fromURI(INITIATION_TEST_HTTPS_URI)).toEqual({
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
      issuerState: 'eyJhbGciOiJSU0Et...FYUaBy',
      original_credential_offer: {
        credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
        issuer: 'https://server.example.com',
        op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
      },
      scheme: 'https',
      supportedFlows: ['Authorization Code Flow'],
      userPinRequired: false,
      version: 1008,
    });
  });

  it('Should return Issuance Initiation Request with base URL from openid-initiate-issuance URI', async () => {
    expect(await CredentialOfferClientV1_0_11.fromURI(INITIATION_TEST_URI_V1_0_08)).toEqual(INITIATION_TEST_V1_0_08);
  });

  it('Should return Issuance Initiation URI from request', async () => {
    expect(CredentialOfferClientV1_0_11.toURI(INITIATION_TEST_V1_0_08)).toEqual(INITIATION_TEST_URI_V1_0_08);
  });

  it('Should return URI from Issuance Initiation Request', async () => {
    const issuanceInitiationClient = await CredentialOfferClientV1_0_11.fromURI(INITIATION_TEST_HTTPS_URI_V1_0_11);
    expect(CredentialOfferClient.toURI(issuanceInitiationClient)).toEqual(INITIATION_TEST_HTTPS_URI_V1_0_11);
  });

  it('Should throw error on invalid URI', async () => {
    const issuanceInitiationURI = INITIATION_TEST_HTTPS_URI.replace('?', '');
    await expect(async () => CredentialOfferClientV1_0_11.fromURI(issuanceInitiationURI)).rejects.toThrow('Invalid Credential Offer Request');
  });

  it('Should return Credential Offer', async () => {
    const client = await CredentialOfferClientV1_0_11.fromURI(
      'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Flaunchpad.vii.electron.mattrlabs.io%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22ldp_vc%22%2C%22types%22%3A%5B%22OpenBadgeCredential%22%5D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22UPZohaodPlLBnGsqB02n2tIupCIg8nKRRUEUHWA665X%22%7D%7D%7D',
    );
    expect(client.version).toEqual(OpenId4VCIVersion.VER_1_0_11);
    expect(client.baseUrl).toEqual('openid-credential-offer://');
    expect(client.scheme).toEqual('openid-credential-offer');
    expect(client.credential_offer.credential_issuer).toEqual('https://launchpad.vii.electron.mattrlabs.io');
    expect(client.preAuthorizedCode).toEqual('UPZohaodPlLBnGsqB02n2tIupCIg8nKRRUEUHWA665X');
  });
});
