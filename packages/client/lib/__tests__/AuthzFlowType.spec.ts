import { AuthzFlowType, CredentialOfferPayloadV1_0_09 } from '@sphereon/openid4vci-common';

//todo: this file is just testing v9, we probably want to add v11 tests here as well
describe('Authorization Flow Type determination', () => {
  it('should return authorization code flow type with a single credential_type', () => {
    expect(
      AuthzFlowType.valueOf({
        issuer: 'test',
        credential_type: 'test',
      } as CredentialOfferPayloadV1_0_09)
    ).toEqual(AuthzFlowType.AUTHORIZATION_CODE_FLOW);
  });
  it('should return authorization code flow type with a credential_type array', () => {
    expect(
      AuthzFlowType.valueOf({
        issuer: 'test',
        credential_type: ['test', 'test1'],
      } as CredentialOfferPayloadV1_0_09)
    ).toEqual(AuthzFlowType.AUTHORIZATION_CODE_FLOW);
  });
  it('should return pre-authorized code flow with a single credential_type', () => {
    expect(
      AuthzFlowType.valueOf({
        issuer: 'test',
        credential_type: 'test',
        'pre-authorized_code': 'test',
      } as CredentialOfferPayloadV1_0_09)
    ).toEqual(AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW);
  });
  it('should return pre-authorized code flow with a credential_type array', () => {
    expect(
      AuthzFlowType.valueOf({
        issuer: 'test',
        credential_type: ['test', 'test1'],
        'pre-authorized_code': 'test',
      } as CredentialOfferPayloadV1_0_09)
    ).toEqual(AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW);
  });
});
