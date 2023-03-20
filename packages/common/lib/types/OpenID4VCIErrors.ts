export const BAD_PARAMS = 'Wrong parameters provided';
export const URL_NOT_VALID = 'Request url is not valid';
export const JWS_NOT_VALID = 'JWS is not valid';
export const PROOF_CANT_BE_CONSTRUCTED = "Proof can't be constructed.";
export const NO_JWT_PROVIDED = 'No JWT provided';
//fixme: do we want the above? the document just talke about the following error codes (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#name-credential-error-response)
export const invalid_request = 'invalid_request'; // Credential Request was malformed. One or more of the parameters (i.e. format, proof) are missing or malformed.
export const invalid_token = 'invalid_token'; // Credential Request contains the wrong Access Token or the Access Token is missing
export const unsupported_credential_type = 'unsupported_credential_type'; // requested credential type is not supported
export const unsupported_credential_format = 'unsupported_credential_format'; // requested credential format is not supported
export const invalid_or_missing_proof = 'invalid_or_missing_proof'; // Credential Request did not contain a proof, or proof was invalid, i.e. it was not bound to a Credential Issuer provided nonce
