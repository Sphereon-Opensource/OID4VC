import { VcIssuanceClient } from '../src/main/VcIssuanceClient';
import { CredentialRequest, ProofType } from '../src/main/types';

describe('VcIssuanceClient ', () => {
  it('should build correctly provided with correct params', function () {
    const vcIssuanceClient = VcIssuanceClient.builder()
      .withCredentialRequestUrl('oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .build();
    expect(vcIssuanceClient._issuanceRequestOpts.credentialRequestUrl).toBe('oidc4vci.demo.spruceid.com/credential');
  });

  it('should build credential request correctly', function () {
    const vcIssuanceClient = VcIssuanceClient.builder()
      .withCredentialRequestUrl('oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .withCredentialType('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential')
      .build();
    const credentialRequest: CredentialRequest = vcIssuanceClient.createCredentialRequest({
        proof: {
            proof_type: ProofType.JWT,
            jwt: 'eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM',
        }
    });
    expect(credentialRequest.type).toBe(
      'https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential'
    );
  });
});
