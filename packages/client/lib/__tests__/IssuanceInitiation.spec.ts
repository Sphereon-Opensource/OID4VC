import { OpenId4VCIVersion } from '@sphereon/oid4vci-common';

import { CredentialOfferClient } from '../CredentialOfferClient';

import { INITIATION_TEST, INITIATION_TEST_HTTPS_URI, INITIATION_TEST_URI } from './MetadataMocks';

describe('Issuance Initiation', () => {
  it('Should return Issuance Initiation Request with base URL from openid-initiate-issuance URI', async () => {
    expect(await CredentialOfferClient.fromURI(INITIATION_TEST_URI)).toEqual(INITIATION_TEST);
  });

  it('Should return Issuance Initiation URI from request', async () => {
    expect(CredentialOfferClient.toURI(INITIATION_TEST)).toEqual('openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fjff.walt.id%2Fissuer-api%2Foidc%2F%22%2C%22credential_configuration_ids%22%3A%5B%22OpenBadgeCredential%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhOTUyZjUxNi1jYWVmLTQ4YjMtODIxYy00OTRkYzgyNjljZjAiLCJwcmUtYXV0aG9yaXplZCI6dHJ1ZX0.YE5DlalcLC2ChGEg47CQDaN1gTxbaQqSclIVqsSAUHE%22%2C%22tx_code%22%3A%7B%22description%22%3A%22Pleaseprovide%20the%20one-time%20code%20that%20was%20sent%20via%20e-mail%22%2C%22input_mode%22%3A%22numeric%22%2C%22length%22%3A4%7D%7D%7D%7D');
  });

  it('Should throw error on invalid URI', async () => {
    const issuanceInitiationURI = INITIATION_TEST_HTTPS_URI.replace('?', '');
    await expect(async () => CredentialOfferClient.fromURI(issuanceInitiationURI)).rejects.toThrowError('Invalid Credential Offer Request');
  });

  it('Should return Credential Offer', async () => {
    const client = await CredentialOfferClient.fromURI(
      'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Flaunchpad.vii.electron.mattrlabs.io%22%2C%22credential_configuration_ids%22%3A%5B%7B%22format%22%3A%22ldp_vc%22%2C%22types%22%3A%5B%22OpenBadgeCredential%22%5D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22UPZohaodPlLBnGsqB02n2tIupCIg8nKRRUEUHWA665X%22%7D%7D%7D',
    );
    expect(client.version).toEqual(OpenId4VCIVersion.VER_1_0_13);
    expect(client.baseUrl).toEqual('openid-credential-offer://');
    expect(client.scheme).toEqual('openid-credential-offer');
    expect(client.credential_offer.credential_issuer).toEqual('https://launchpad.vii.electron.mattrlabs.io');
    expect(client.preAuthorizedCode).toEqual('UPZohaodPlLBnGsqB02n2tIupCIg8nKRRUEUHWA665X');
  });
});
