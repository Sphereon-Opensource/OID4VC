import { Alg } from './CredentialIssuance.types';

export const BAD_PARAMS = 'Wrong parameters provided';
export const URL_NOT_VALID = 'Request url is not valid';
export const JWS_NOT_VALID = 'JWS is not valid';
export const PROOF_CANT_BE_CONSTRUCTED = "Proof can't be constructed.";
export const NO_JWT_PROVIDED = 'No JWT provided';
export const TYP_ERROR = 'Typ must be "openid4vci-proof+jwt"';
export const ALG_ERROR = `Algorithm is a required field and must be one of: ${Object.keys(Alg).join(', ')}`;
export const KID_JWK_X5C_ERROR = 'Only one must be present: kid, jwk or x5c';
export const ISS_ERROR = 'iss must be the client_id or must be omitted if pre-authorized through anonymous access to the token endpoint';
export const AUD_ERROR = 'aud must be the URL of the credential issuer';
export const IAT_ERROR = 'iat must be the time at which the proof was issued';
export const NONCE_ERROR = 'nonce must be c_nonce provided by the credential issuer';
export const JWT_VERIFY_CONFIG_ERROR = 'JWT verify callback not configured correctly.';
export const ISSUER_CONFIG_ERROR = 'Issuer not configured correctly.';
