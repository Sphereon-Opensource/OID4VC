import { Alg } from './CredentialIssuance.types';

export const BAD_PARAMS = 'Wrong parameters provided';
export const URL_NOT_VALID = 'Request url is not valid';
export const JWS_NOT_VALID = 'JWS is not valid';
export const PROOF_CANT_BE_CONSTRUCTED = "Proof can't be constructed.";
export const NO_JWT_PROVIDED = 'No JWT provided';
export const TYP_ERROR = 'Typ must be "openid4vci-proof+jwt"';
export const ALG_ERROR = `Algorithm is a required field, you are free to use the signing algorithm of your choice or one of the following: ${Object.keys(
  Alg,
).join(', ')}`;
export const KID_JWK_X5C_ERROR = 'Only one must be present: kid, jwk or x5c';
export const KID_DID_NO_DID_ERROR = 'A DID value needs to be returned when kid is present';
export const DID_NO_DIDDOC_ERROR = 'A DID Document needs to be resolved when a DID is encountered';
export const AUD_ERROR = 'aud must be the URL of the credential issuer';
export const IAT_ERROR = 'iat must be the time at which the proof was issued';
export const NONCE_ERROR = 'nonce must be c_nonce provided by the credential issuer';
export const JWT_VERIFY_CONFIG_ERROR = 'JWT verify callback not configured correctly.';
export const ISSUER_CONFIG_ERROR = 'Issuer not configured correctly.';
export const UNKNOWN_CLIENT_ERROR = 'The client is not known by the issuer';
export const NO_ISS_IN_AUTHORIZATION_CODE_CONTEXT = 'iss missing in authorization-code context';
export const ISS_PRESENT_IN_PRE_AUTHORIZED_CODE_CONTEXT = 'iss should be omitted in pre-authorized-code context';
export const ISS_MUST_BE_CLIENT_ID = 'iss must be the client id';
export const GRANTS_MUST_NOT_BE_UNDEFINED = 'Grants must not be undefined';
export const STATE_MISSING_ERROR = 'issuer state or pre-authorized key not found';
export const CREDENTIAL_MISSING_ERROR = 'Credential must be present in response';
export const UNSUPPORTED_GRANT_TYPE_ERROR = 'unsupported grant_type';
export const PRE_AUTHORIZED_CODE_REQUIRED_ERROR = 'pre-authorized_code is required';
export const USER_PIN_REQUIRED_ERROR = 'User pin is required';
export const USER_PIN_NOT_REQUIRED_ERROR = 'User pin is not required';
export const PIN_VALIDATION_ERROR = 'PIN must consist of maximum 8 numeric characters';
export const PIN_NOT_MATCH_ERROR = 'PIN is invalid';
export const INVALID_PRE_AUTHORIZED_CODE = 'pre-authorized_code is invalid';
export const EXPIRED_PRE_AUTHORIZED_CODE = 'pre-authorized_code is expired';
export const JWT_SIGNER_CALLBACK_REQUIRED_ERROR = 'JWT signer callback function is required';
export const STATE_MANAGER_REQUIRED_ERROR = 'StateManager instance is required';
export const NONCE_STATE_MANAGER_REQUIRED_ERROR = 'NonceStateManager instance is required';
export const PIN_NOT_MATCHING_ERROR = 'PIN does not match';
export const ACCESS_TOKEN_ISSUER_REQUIRED_ERROR = 'access token issuer is required';
