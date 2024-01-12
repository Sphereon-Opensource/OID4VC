import Debug from 'debug';

import {
  AssertedUniformCredentialOffer,
  AuthzFlowType,
  CredentialOffer,
  CredentialOfferPayload,
  CredentialOfferPayloadV1_0_12,
  DefaultURISchemes,
  Grant,
  GrantTypes,
  OpenId4VCIVersion,
  OpenIDResponse,
  UniformCredentialOffer,
  UniformCredentialOfferPayload,
  UniformCredentialOfferRequest,
} from '../types';

import { getJson } from './HttpUtils';

const debug = Debug('sphereon:oid4vci:offer');

export function determineSpecVersionFromURI(uri: string): OpenId4VCIVersion {
  let version: OpenId4VCIVersion = OpenId4VCIVersion.VER_UNKNOWN;

  version = determineSpecVersionFromScheme(uri, version);
  version = getVersionFromURIParam(uri, version, OpenId4VCIVersion.VER_UNSUPPORTED, 'initiate_issuance');
  version = getVersionFromURIParam(uri, version, OpenId4VCIVersion.VER_UNSUPPORTED, 'credential_type');
  version = getVersionFromURIParam(uri, version, OpenId4VCIVersion.VER_UNSUPPORTED, 'op_state');

  // version = getVersionFromURIParam(uri, version, OpenId4VCIVersion.VER_1_0_09, 'credentials');
  // version = getVersionFromURIParam(uri, version, OpenId4VCIVersion.VER_1_0_09, 'initiate_issuance_uri')

  version = getVersionFromURIParam(uri, version, OpenId4VCIVersion.VER_1_0_12, 'credential_offer_uri=');
  version = getVersionFromURIParam(uri, version, OpenId4VCIVersion.VER_1_0_12, 'credential_issuer');
  version = getVersionFromURIParam(uri, version, OpenId4VCIVersion.VER_1_0_12, 'grants');

/*
  if (version === OpenId4VCIVersion.VER_UNKNOWN) {  Why would we impose a version when required parameters are missing? If we need it for a specific case, please add a comment.
    version = OpenId4VCIVersion.VER_1_0_12;
  }
*/
  return version;
}

export function determineSpecVersionFromScheme(credentialOfferURI: string, openId4VCIVersion: OpenId4VCIVersion) {
  const scheme = getScheme(credentialOfferURI);
  if (credentialOfferURI.includes(DefaultURISchemes.INITIATE_ISSUANCE)) {
    return recordVersion(openId4VCIVersion, OpenId4VCIVersion.VER_UNSUPPORTED, scheme);
  } else if (credentialOfferURI.includes(DefaultURISchemes.CREDENTIAL_OFFER)) {
    return recordVersion(openId4VCIVersion, OpenId4VCIVersion.VER_1_0_12, scheme);
  } else {
    return recordVersion(openId4VCIVersion, OpenId4VCIVersion.VER_UNKNOWN, scheme);
  }
}

export function getScheme(credentialOfferURI: string) {
  if (!credentialOfferURI || !credentialOfferURI.includes('://')) {
    throw Error('Invalid credential offer URI');
  }
  return credentialOfferURI.split('://')[0];
}

export function getIssuerFromCredentialOfferPayload(request: CredentialOfferPayload): string | undefined{
  if (!request || (!('issuer' in request) && !('credential_issuer' in request))) {
    return undefined;
  }
  return request['credential_issuer'];
}

export function determineSpecVersionFromOffer(offer: CredentialOfferPayload | CredentialOffer): OpenId4VCIVersion {
  if (isCredentialOfferV1_0_12(offer)) {
    return OpenId4VCIVersion.VER_1_0_12;
  }
  return OpenId4VCIVersion.VER_UNKNOWN;
}

export function isCredentialOfferVersion(offer: CredentialOfferPayload | CredentialOffer, min: OpenId4VCIVersion, max?: OpenId4VCIVersion) {
  if (max && max.valueOf() < min.valueOf()) {
    throw Error(`Cannot have a max ${max.valueOf()} version smaller than the min version ${min.valueOf()}`);
  }
  const version = determineSpecVersionFromOffer(offer);
  if (version.valueOf() < min.valueOf()) {
    debug(`Credential offer version (${version.valueOf()}) is lower than minimum required version (${min.valueOf()})`);
    return false;
  } else if (max && version.valueOf() > max.valueOf()) {
    debug(`Credential offer version (${version.valueOf()}) is higher than maximum required version (${max.valueOf()})`);
    return false;
  }
  return true;
}

function isCredentialOfferV1_0_12(offer: CredentialOfferPayload | CredentialOffer): boolean {
  if (!offer) {
    return false;
  }
  if ('credential_issuer' in offer && 'credentials' in offer) {
    // payload
    return true;
  }
  if ('credential_offer' in offer && offer['credential_offer']) {
    // offer, so check payload
    return isCredentialOfferV1_0_12(offer['credential_offer']);
  }
  return 'credential_offer_uri' in offer;
}

export async function toUniformCredentialOfferRequest(
  offer: CredentialOffer,
  opts?: {
    resolve?: boolean;
    version?: OpenId4VCIVersion;
  },
): Promise<UniformCredentialOfferRequest> {
  const version = opts?.version ?? determineSpecVersionFromOffer(offer);
  let originalCredentialOffer = offer.credential_offer;
  let credentialOfferURI: string | undefined;
  if ('credential_offer_uri' in offer && offer?.credential_offer_uri !== undefined) {
    credentialOfferURI = offer.credential_offer_uri;
    if (opts?.resolve || opts?.resolve === undefined) {
      originalCredentialOffer = (await resolveCredentialOfferURI(credentialOfferURI)) as CredentialOfferPayloadV1_0_12;
    } else if (!originalCredentialOffer) {
      throw Error(`Credential offer uri (${credentialOfferURI}) found, but resolution was explicitly disabled and credential_offer was supplied`);
    }
  }
  if (!originalCredentialOffer) {
    throw Error('No credential offer available');
  }
  const payload = toUniformCredentialOfferPayload(originalCredentialOffer, opts);
  const supportedFlows = determineFlowType(payload, version);
  return {
    credential_offer: payload,
    original_credential_offer: originalCredentialOffer,
    ...(credentialOfferURI && { credential_offer_uri: credentialOfferURI }),
    supportedFlows,
    version,
  };
}

export function isPreAuthCode(request: UniformCredentialOfferPayload | UniformCredentialOffer) {
  const payload = 'credential_offer' in request ? request.credential_offer : (request as UniformCredentialOfferPayload);
  return payload?.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code'] !== undefined;
}

export async function assertedUniformCredentialOffer(
  origCredentialOffer: UniformCredentialOffer,
  opts?: {
    resolve?: boolean;
  },
): Promise<AssertedUniformCredentialOffer> {
  const credentialOffer = JSON.parse(JSON.stringify(origCredentialOffer));
  if (credentialOffer.credential_offer_uri && !credentialOffer.credential_offer) {
    if (opts?.resolve === undefined || opts.resolve) {
      credentialOffer.credential_offer = await resolveCredentialOfferURI(credentialOffer.credential_offer_uri);
    } else {
      throw Error(`No credential_offer present, but we did get a URI, but resolution was explicitly disabled`);
    }
  }
  if (!credentialOffer.credential_offer) {
    throw Error(`No credential_offer present`);
  }
  credentialOffer.credential_offer = await toUniformCredentialOfferPayload(credentialOffer.credential_offer, { version: credentialOffer.version });
  return credentialOffer as AssertedUniformCredentialOffer;
}

export async function resolveCredentialOfferURI(uri?: string): Promise<UniformCredentialOfferPayload | undefined> {
  if (!uri) {
    return undefined;
  }
  const response = (await getJson(uri)) as OpenIDResponse<UniformCredentialOfferPayload>;
  if (!response || !response.successBody) {
    throw Error(`Could not get credential offer from uri: ${uri}: ${JSON.stringify(response?.errorBody)}`);
  }
  return response.successBody as UniformCredentialOfferPayload;
}

export function toUniformCredentialOfferPayload(
  offer: CredentialOfferPayload,
  opts?: {
    version?: OpenId4VCIVersion;
  },
): UniformCredentialOfferPayload {
  // todo: create test to check idempotence once a payload is already been made uniform.
  const version = opts?.version ?? determineSpecVersionFromOffer(offer);
  if (version >= OpenId4VCIVersion.VER_1_0_12) {
    const orig = offer as UniformCredentialOfferPayload;
    return {
      ...orig,
    };
  }
  throw Error(`Could not create uniform payload for version ${version}`);
}

export function determineFlowType(
  suppliedOffer: AssertedUniformCredentialOffer | UniformCredentialOfferPayload,
  version: OpenId4VCIVersion,
): AuthzFlowType[] {
  const payload: UniformCredentialOfferPayload = getCredentialOfferPayload(suppliedOffer);
  const supportedFlows: AuthzFlowType[] = [];
  if (payload.grants?.authorization_code) {
    supportedFlows.push(AuthzFlowType.AUTHORIZATION_CODE_FLOW);
  }
  if (payload.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code']) {
    supportedFlows.push(AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW);
  }
  return supportedFlows;
}

export function getCredentialOfferPayload(offer: AssertedUniformCredentialOffer | UniformCredentialOfferPayload): UniformCredentialOfferPayload {
  let payload: UniformCredentialOfferPayload;
  if ('credential_offer' in offer && offer['credential_offer']) {
    payload = offer.credential_offer;
  } else {
    payload = offer as UniformCredentialOfferPayload;
  }
  return payload;
}

export function determineGrantTypes(
  offer:
    | AssertedUniformCredentialOffer
    | UniformCredentialOfferPayload
    | ({
        grants: Grant;
      } & Record<never, never>),
): GrantTypes[] {
  let grants: Grant | undefined;
  if ('grants' in offer && offer.grants) {
    grants = offer.grants;
  } else {
    grants = getCredentialOfferPayload(offer as AssertedUniformCredentialOffer | UniformCredentialOfferPayload).grants;
  }

  const types: GrantTypes[] = [];
  if (grants) {
    if (grants.authorization_code) {
      types.push(GrantTypes.AUTHORIZATION_CODE);
    }
    if (
      grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'] &&
      grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code']
    ) {
      types.push(GrantTypes.PRE_AUTHORIZED_CODE);
    }
  }
  return types;
}

function getVersionFromURIParam(credentialOfferURI: string, currentVersion: OpenId4VCIVersion, matchingVersion: OpenId4VCIVersion, param: string) {
  if (credentialOfferURI.includes(param)) {
    return recordVersion(currentVersion, matchingVersion, param);
  }
  return currentVersion;
}

function recordVersion(currentVersion: OpenId4VCIVersion, matchingVersion: OpenId4VCIVersion, key: string) {
  if (currentVersion === OpenId4VCIVersion.VER_UNKNOWN || matchingVersion === currentVersion) {
    return matchingVersion;
  }

  throw new Error(
    `Invalid param. Some keys have been used from version: ${currentVersion} version while '${key}' is used from version: ${matchingVersion}`,
  );
}

export function getTypesFromOffer(credentialOffer: UniformCredentialOfferPayload, opts?: { filterVerifiableCredential: boolean }) {
  const types = credentialOffer.credentials.reduce<string[]>((prev, curr) => {
    // FIXME returning the string value is wrong (as it's an id), but just matching the current behavior of this library
    // The credential_type (from draft 8) and the actual 'type' value in a VC (from draft 11) are mixed up
    // Fix for this here: https://github.com/Sphereon-Opensource/OID4VCI/pull/54
    if (typeof curr === 'string') {
      return [...prev, curr];
    } else if (curr.format === 'jwt_vc_json-ld' || curr.format === 'ldp_vc') {
      return [...prev, ...curr.credential_definition.type];
    } else if (curr.format === 'jwt_vc_json' || curr.format === 'jwt_vc') {
      return [...prev, ...curr.types];
    } else if (curr.format === 'vc+sd-jwt') {
      return [...prev, curr.vct];
    }

    return prev;
  }, []);

  if (!types || types.length === 0) {
    throw Error('Could not deduce types from credential offer');
  }
  if (opts?.filterVerifiableCredential) {
    return types.filter((type) => type !== 'VerifiableCredential');
  }
  return types;
}
