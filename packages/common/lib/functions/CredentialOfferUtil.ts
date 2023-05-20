import {
  AssertedUniformCredentialOffer,
  CredentialOffer,
  CredentialOfferPayload,
  CredentialOfferPayloadV1_0_08,
  CredentialOfferPayloadV1_0_09,
  CredentialOfferPayloadV1_0_11,
  DefaultURISchemes,
  Grant,
  OpenId4VCIVersion,
  OpenIDResponse,
  UniformCredentialOffer,
  UniformCredentialOfferPayload,
  UniformCredentialOfferRequest,
} from '../types';

import { getJson } from './HttpUtils';

export function determineSpecVersionFromURI(uri: string): OpenId4VCIVersion {
  let version: OpenId4VCIVersion = OpenId4VCIVersion.VER_UNKNOWN;

  version = determineSpecVersionFromScheme(uri, version);
  version = getVersionFromURIParam(uri, version, OpenId4VCIVersion.VER_1_0_08, 'initiate_issuance');
  version = getVersionFromURIParam(uri, version, OpenId4VCIVersion.VER_1_0_08, 'credential_type');
  version = getVersionFromURIParam(uri, version, OpenId4VCIVersion.VER_1_0_08, 'op_state');

  // version = getVersionFromURIParam(uri, version, OpenId4VCIVersion.VER_1_0_09, 'credentials');
  // version = getVersionFromURIParam(uri, version, OpenId4VCIVersion.VER_1_0_09, 'initiate_issuance_uri')

  version = getVersionFromURIParam(uri, version, OpenId4VCIVersion.VER_1_0_11, 'credential_offer_uri=');
  version = getVersionFromURIParam(uri, version, OpenId4VCIVersion.VER_1_0_11, 'credential_issuer');
  version = getVersionFromURIParam(uri, version, OpenId4VCIVersion.VER_1_0_11, 'grants');

  if (version === OpenId4VCIVersion.VER_UNKNOWN) {
    version = OpenId4VCIVersion.VER_1_0_11;
  }
  return version;
}

export function determineSpecVersionFromScheme(credentialOfferURI: string, openId4VCIVersion: OpenId4VCIVersion) {
  const scheme = getScheme(credentialOfferURI);
  if (credentialOfferURI.includes(DefaultURISchemes.INITIATE_ISSUANCE)) {
    return recordVersion(openId4VCIVersion, OpenId4VCIVersion.VER_1_0_08, scheme);
  } else if (credentialOfferURI.includes(DefaultURISchemes.CREDENTIAL_OFFER)) {
    return recordVersion(openId4VCIVersion, OpenId4VCIVersion.VER_1_0_11, scheme);
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

export function getIssuerFromCredentialOfferPayload(request: CredentialOfferPayload): string | undefined {
  if (!request || (!('issuer' in request) && !('credential_issuer' in request))) {
    return undefined;
  }
  return 'issuer' in request ? request.issuer : request['credential_issuer'];
}

export function determineSpecVersionFromOffer(offer: CredentialOfferPayload | CredentialOffer): OpenId4VCIVersion {
  if (isCredentialOfferV1_0_11(offer)) {
    return OpenId4VCIVersion.VER_1_0_11;
  } else if (isCredentialOfferV1_0_09(offer)) {
    return OpenId4VCIVersion.VER_1_0_09;
  } else if (isCredentialOfferV1_0_08(offer)) {
    return OpenId4VCIVersion.VER_1_0_08;
  }
  return OpenId4VCIVersion.VER_UNKNOWN;
}

export function isCredentialOfferVersion(offer: CredentialOfferPayload | CredentialOffer, min: OpenId4VCIVersion, max?: OpenId4VCIVersion) {
  if (max && max.valueOf() < min.valueOf()) {
    throw Error(`Cannot have a max ${max.valueOf()} version smaller than the min version ${min.valueOf()}`);
  }
  const version = determineSpecVersionFromOffer(offer);
  if (version.valueOf() < min.valueOf()) {
    throw Error(`Credential offer version (${version.valueOf()}) is lower than minimum required version (${min.valueOf()})`);
  } else if (max && version.valueOf() > max.valueOf()) {
    throw Error(`Credential offer version (${version.valueOf()}) is higher than maximum required version (${max.valueOf()})`);
  }
  return true;
}

function isCredentialOfferV1_0_08(offer: CredentialOfferPayload | CredentialOffer): boolean {
  if (!offer) {
    return false;
  }
  if ('issuer' in offer && 'credential_type' in offer) {
    // payload
    return true;
  }
  if ('credential_offer' in offer && offer['credential_offer']) {
    // offer, so check payload
    return isCredentialOfferV1_0_08(offer['credential_offer']);
  }
  return false;
}

function isCredentialOfferV1_0_09(offer: CredentialOfferPayload | CredentialOffer): boolean {
  if (!offer) {
    return false;
  }
  if ('issuer' in offer && 'credentials' in offer) {
    // payload
    return true;
  }
  if ('credential_offer' in offer && offer['credential_offer']) {
    // offer, so check payload
    return isCredentialOfferV1_0_09(offer['credential_offer']);
  }
  return false;
}

function isCredentialOfferV1_0_11(offer: CredentialOfferPayload | CredentialOffer): boolean {
  if (!offer) {
    return false;
  }
  if ('credential_issuer' in offer && 'credentials' in offer) {
    // payload
    return true;
  }
  if ('credential_offer' in offer && offer['credential_offer']) {
    // offer, so check payload
    return isCredentialOfferV1_0_11(offer['credential_offer']);
  }
  return 'credential_offer_uri' in offer;
}

export async function toUniformCredentialOfferRequest(
  offer: CredentialOffer,
  opts?: {
    resolve?: boolean;
    version?: OpenId4VCIVersion;
  }
): Promise<UniformCredentialOfferRequest> {
  const version = opts?.version ?? determineSpecVersionFromOffer(offer);
  let originalCredentialOffer = offer.credential_offer;
  let credentialOfferURI: string | undefined;
  if ('credential_offer_uri' in offer && offer?.credential_offer_uri !== undefined) {
    if (opts?.resolve || opts?.resolve === undefined) {
      credentialOfferURI = offer.credential_offer_uri;
      originalCredentialOffer = (await resolveCredentialOfferURI(credentialOfferURI)) as CredentialOfferPayloadV1_0_11;
    } else if (!originalCredentialOffer) {
      throw Error(`Credential offer uri (${credentialOfferURI}) found, but resolution was explicitly disabled and credential_offer was supplied`);
    }
  }
  if (!originalCredentialOffer) {
    throw Error('No credential offer available');
  }
  return {
    credential_offer: toUniformCredentialOfferPayload(originalCredentialOffer, opts),
    original_credential_offer: originalCredentialOffer,
    ...(credentialOfferURI && { credential_offer_uri: credentialOfferURI }),
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
  }
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
  credentialOffer.credential_offer = await toUniformCredentialOfferPayload(credentialOffer.credential_offer);
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
  }
): UniformCredentialOfferPayload {
  const version = opts?.version ?? determineSpecVersionFromOffer(offer);
  if (version >= OpenId4VCIVersion.VER_1_0_11) {
    const orig = offer as UniformCredentialOfferPayload;
    return {
      ...orig,
    };
  }
  const grants: Grant = {};
  let offerPayloadAsV8V9 = offer as CredentialOfferPayloadV1_0_08 | CredentialOfferPayloadV1_0_09;
  if (isCredentialOfferVersion(offer, OpenId4VCIVersion.VER_1_0_08, OpenId4VCIVersion.VER_1_0_09)) {
    if (offerPayloadAsV8V9.op_state) {
      grants.authorization_code = {
        issuer_state: offerPayloadAsV8V9.op_state,
      };
    }
    let user_pin_required = false;
    if (typeof offerPayloadAsV8V9.user_pin_required === 'string') {
      user_pin_required = offerPayloadAsV8V9.user_pin_required === 'true' || offerPayloadAsV8V9.user_pin_required === 'yes';
    } else if (offerPayloadAsV8V9.user_pin_required !== undefined) {
      user_pin_required = offerPayloadAsV8V9.user_pin_required;
    }
    if (offerPayloadAsV8V9['pre-authorized_code']) {
      grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'] = {
        'pre-authorized_code': offerPayloadAsV8V9['pre-authorized_code'],
        user_pin_required,
      };
    }
  }
  if (version === OpenId4VCIVersion.VER_1_0_09) {
    offerPayloadAsV8V9 = offer as CredentialOfferPayloadV1_0_09;
    return {
      // credential_definition: getCredentialsSupported(never, offerPayloadAsV8V9.credentials).map(sup => {credentialSubject: sup.credentialSubject})[0],
      credential_issuer: offerPayloadAsV8V9.issuer,
      credentials: offerPayloadAsV8V9.credentials,
      grants,
    };
  }
  if (version === OpenId4VCIVersion.VER_1_0_08) {
    offerPayloadAsV8V9 = offer as CredentialOfferPayloadV1_0_08;
    return {
      credential_issuer: offerPayloadAsV8V9.issuer,
      credentials: Array.isArray(offerPayloadAsV8V9.credential_type) ? offerPayloadAsV8V9.credential_type : [offerPayloadAsV8V9.credential_type],
      grants,
    } as UniformCredentialOfferPayload;
  }
  throw Error(`Could not create uniform payload for version ${version}`);
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
    `Invalid param. Some keys have been used from version: ${currentVersion} version while '${key}' is used from version: ${matchingVersion}`
  );
}
