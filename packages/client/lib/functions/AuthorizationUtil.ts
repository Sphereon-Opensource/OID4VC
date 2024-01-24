import { assertValidCodeVerifier, CodeChallengeMethod, createCodeChallenge, generateCodeVerifier, PKCEOpts } from '@sphereon/oid4vci-common';

export const generateMissingPKCEOpts = (pkce: PKCEOpts) => {
  if (pkce.disabled) {
    return pkce;
  }
  if (!pkce.codeChallengeMethod) {
    pkce.codeChallengeMethod = CodeChallengeMethod.S256;
  }
  if (!pkce.codeVerifier) {
    pkce.codeVerifier = generateCodeVerifier();
  }
  assertValidCodeVerifier(pkce.codeVerifier);
  if (!pkce.codeChallenge) {
    pkce.codeChallenge = createCodeChallenge(pkce.codeVerifier, pkce.codeChallengeMethod);
  }
  return pkce;
};
