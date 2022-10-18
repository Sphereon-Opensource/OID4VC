import { AuthzFlowType } from '../lib';

describe('Authorization Flow Type determination', () => {
  it('should return authorization code flow type with a single credential_type', () => {
    expect(
      AuthzFlowType.valueOf({
        issuer: 'test',
        credential_type: 'test',
      })
    ).toEqual(AuthzFlowType.AUTHORIZATION_CODE_FLOW);
  });
  it('should return authorization code flow type with a credential_type array', () => {
    expect(
      AuthzFlowType.valueOf({
        issuer: 'test',
        credential_type: ['test', 'test1'],
      })
    ).toEqual(AuthzFlowType.AUTHORIZATION_CODE_FLOW);
  });
  it('should return pre-authorized code flow with a single credential_type', () => {
    expect(
      AuthzFlowType.valueOf({
        issuer: 'test',
        credential_type: 'test',
        'pre-authorized_code': 'test',
      })
    ).toEqual(AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW);
  });
  it('should return pre-authorized code flow with a credential_type array', () => {
    expect(
      AuthzFlowType.valueOf({
        issuer: 'test',
        credential_type: ['test', 'test1'],
        'pre-authorized_code': 'test',
      })
    ).toEqual(AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW);
  });
});
