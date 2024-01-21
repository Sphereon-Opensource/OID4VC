import { AuthorizationResponseOpts, mergeOAuth2AndOpenIdInRequestPayload } from '../authorization-response';
import { assertValidResponseOpts } from '../authorization-response/Opts';
import { authorizationRequestVersionDiscovery } from '../helpers/SIOPSpecVersion';
import {
  IDTokenPayload,
  isSuppliedSignature,
  JWK,
  ResponseIss,
  SIOPErrors,
  SubjectSyntaxTypesSupportedValues,
  SupportedVersion,
  VerifiedAuthorizationRequest,
} from '../types';

export const createIDTokenPayload = async (
  verifiedAuthorizationRequest: VerifiedAuthorizationRequest,
  responseOpts: AuthorizationResponseOpts,
): Promise<IDTokenPayload> => {
  assertValidResponseOpts(responseOpts);
  const authorizationRequestPayload = await verifiedAuthorizationRequest.authorizationRequest.mergedPayloads();
  const requestObject = verifiedAuthorizationRequest.requestObject;
  if (!authorizationRequestPayload) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
  const payload = await mergeOAuth2AndOpenIdInRequestPayload(authorizationRequestPayload, requestObject);

  const supportedDidMethods = verifiedAuthorizationRequest.registrationMetadataPayload.subject_syntax_types_supported.filter((sst) =>
    sst.includes(SubjectSyntaxTypesSupportedValues.DID.valueOf()),
  );
  const state = payload.state;
  const nonce = payload.nonce;
  const SEC_IN_MS = 1000;

  const rpSupportedVersions = authorizationRequestVersionDiscovery(payload);
  const maxRPVersion = rpSupportedVersions.reduce(
    (previous, current) => (current.valueOf() > previous.valueOf() ? current : previous),
    SupportedVersion.SIOPv2_ID1,
  );
  if (responseOpts.version && rpSupportedVersions.length > 0 && !rpSupportedVersions.includes(responseOpts.version)) {
    throw Error(`RP does not support spec version ${responseOpts.version}, supported versions: ${rpSupportedVersions.toString()}`);
  }
  const opVersion = responseOpts.version ?? maxRPVersion;

  const idToken: IDTokenPayload = {
    // fixme: ID11 does not use this static value anymore
    iss:
      responseOpts?.registration?.issuer ??
      (opVersion === SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1 ? ResponseIss.JWT_VC_PRESENTATION_V1 : ResponseIss.SELF_ISSUED_V2),
    aud: responseOpts.audience || payload.client_id,
    iat: Math.round(Date.now() / SEC_IN_MS - 60 * SEC_IN_MS),
    exp: Math.round(Date.now() / SEC_IN_MS + (responseOpts.expiresIn || 600)),
    sub: responseOpts.signature.did,
    auth_time: payload.auth_time,
    nonce,
    state,
    // ...(responseOpts.presentationExchange?._vp_token ? { _vp_token: responseOpts.presentationExchange._vp_token } : {}),
  };
  if (supportedDidMethods.indexOf(SubjectSyntaxTypesSupportedValues.JWK_THUMBPRINT) != -1 && !responseOpts.signature.did) {
    const { thumbprint, subJwk } = await createThumbprintAndJWK(responseOpts);
    idToken['sub_jwk'] = subJwk;
    idToken.sub = thumbprint;
  }
  return idToken;
};

const createThumbprintAndJWK = async (resOpts: AuthorizationResponseOpts): Promise<{ thumbprint: string; subJwk: JWK }> => {
  let thumbprint;
  let subJwk;
  /*  if (isInternalSignature(resOpts.signature)) {
    thumbprint = await getThumbprint(resOpts.signature.hexPrivateKey, resOpts.signature.did);
    subJwk = getPublicJWKFromHexPrivateKey(
      resOpts.signature.hexPrivateKey,
      resOpts.signature.kid || `${resOpts.signature.did}#key-1`,
      resOpts.signature.did
    );
  } else*/ if (isSuppliedSignature(resOpts.signature)) {
    // fixme: These are uninitialized. Probably we have to extend the supplied withSignature to provide these.
    return { thumbprint, subJwk };
  } else {
    throw new Error(SIOPErrors.SIGNATURE_OBJECT_TYPE_NOT_SET);
  }
};
