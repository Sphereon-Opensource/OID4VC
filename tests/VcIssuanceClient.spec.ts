import {VcIssuanceClient} from "../src/VcIssuanceClient";

describe('VcIssuanceClient ', () => {
  it('should build correctly provided with correct params', function () {
    const vcIssuanceClient = VcIssuanceClient.builder()
      .withCredentialRequestUrl('oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .build();
    expect(vcIssuanceClient._issuanceRequestOpts.credentialRequestUrl).toBe('oidc4vci.demo.spruceid.com/credential');
  });

  it('should build credential request correctly', function () {
    VcIssuanceClient.builder()
      .withCredentialRequestUrl('oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .withCredentialType('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential')
      .build();
  });
});
