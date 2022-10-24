import { OID4VCIServerMetadata } from './OID4VCIServerMetadata';

export interface ErrorResponse extends Response {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

export const PRE_AUTH_CODE_LITERAL = 'pre-authorized_code';

export enum WellKnownEndpoints {
  OIDC_CONFIGURATION = '/.well-known/openid-configuration',
  OAUTH_AS = '/.well-known/oauth-authorization-server',
  OIDC4VCI = '/.well-known/openid-credential-issuer',
}

export interface EndpointMetadata {
  issuer: string;
  token_endpoint: string;
  credential_endpoint: string;
  oid4vci_metadata?: OID4VCIServerMetadata;
}
