import { DefaultURISchemes, OpenId4VCIVersion } from '../types';

export function determineSpecVersionFromURI(uri: string): OpenId4VCIVersion {
  let version: OpenId4VCIVersion = OpenId4VCIVersion.VER_UNKNOWN;

  if (uri) {
    version = determineSpecVersionFromScheme(uri, version);

    version = getVersion(uri, OpenId4VCIVersion.VER_9, version, 'pre-authorized_code');
    version = getVersion(uri, OpenId4VCIVersion.VER_11, version, 'credential_issuer');
    version = getVersion(uri, OpenId4VCIVersion.VER_11, version, 'cryptographic_binding_methods_supported');
    version = getVersion(uri, OpenId4VCIVersion.VER_11, version, 'cryptographic_suites_supported');
    version = getVersion(uri, OpenId4VCIVersion.VER_11, version, 'credentialSubject');

    return version;
  }

  version = recordVersion(version, OpenId4VCIVersion.VER_11, getScheme(uri));

  return version;
}

export function determineSpecVersionFromScheme(credentialOfferURI: string, openId4VCIVersion: OpenId4VCIVersion) {
  const scheme = getScheme(credentialOfferURI);
  if (credentialOfferURI.startsWith(DefaultURISchemes.CREDENTIAL_OFFER)) {
    return recordVersion(openId4VCIVersion, OpenId4VCIVersion.VER_11, scheme);
  } else {
    return recordVersion(openId4VCIVersion, OpenId4VCIVersion.VER_9, scheme);
  }
}

export function getScheme(credentialOfferURI: string) {
  return credentialOfferURI.split('?')[0];
}

function getVersion(credentialOfferURI: string, expectedVersion: OpenId4VCIVersion, predeterminedVersion: OpenId4VCIVersion, param: string) {
  if (credentialOfferURI.includes(param)) {
    return recordVersion(predeterminedVersion, expectedVersion, param);
  }
  return predeterminedVersion;
}

function recordVersion(determinedVersion: OpenId4VCIVersion, potentialVersion: OpenId4VCIVersion, key: string) {
  if (determinedVersion === OpenId4VCIVersion.VER_UNKNOWN || determinedVersion === potentialVersion) {
    return potentialVersion;
  }

  throw new Error(
    `Invalid param. Some keys have been used from version: ${determinedVersion} version while '${key}' is used from version: ${potentialVersion}`
  );
}
