import { CodeChallengeMethod } from '@sphereon/oid4vci-common';
import { CredentialFormat } from '@sphereon/ssi-types';

export interface AuthDetails {
  type: 'openid_credential' | string;
  locations?: string | string[];
  format: CredentialFormat | CredentialFormat[];

  [s: string]: unknown;
}

/**
 * Determinse whether PAR should be used when supported
 *
 * REQUIRE: Require PAR, if AS does not support it throw an error
 * AUTO: Use PAR is the AS supports it, otherwise construct a reqular URI,
 * NEVER: Do not use PAR even if the AS supports it (not recommended)
 */
export enum PARMode {
  REQUIRE,
  AUTO,
  NEVER,
}

export interface AuthRequestOpts {
  pkce?: PKCEOpts;
  parMode?: PARMode;
  authorizationDetails?: AuthDetails | AuthDetails[];
  redirectUri: string;
  scope?: string;
}

/**
 * Optional options to provide PKCE params like code verifier and challenge yourself, or to disable PKCE altogether. If not provide PKCE will still be used! If individual params are not provide, they will be generated/calculated
 */
export interface PKCEOpts {
  /**
   * PKCE is enabled by default even if you do not provide these options. Set this to true to disable PKCE
   */
  disabled?: boolean;

  /**
   * Provide a code_challenge, otherwise it will be calculated using the code_verifier and method
   */
  codeChallenge?: string;

  /**
   * The code_challenge_method, should always by S256
   */
  codeChallengeMethod?: CodeChallengeMethod;

  /**
   * Provide a code_verifier, otherwise it will be generated
   */
  codeVerifier?: string;
}
