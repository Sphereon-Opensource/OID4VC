import { OpenId4VCIVersion, DefaultURISchemes } from '@sphereon/openid4vci-common';

import { CredentialIssuanceClient } from './CredentialIssuanceClient';
import { CredentialOfferClient } from './CredentialOfferClient';
import { IssuanceInitiationClient } from './IssuanceInitiationClient';

export class CredentialOfferUtil {
  public static determineCredentialIssuanceClient(credentialOfferURI: string): CredentialIssuanceClient {
    if (OpenId4VCIVersion.VER_9 === CredentialOfferUtil.getOpenId4VCIVersion(credentialOfferURI)) {
      return IssuanceInitiationClient.fromURI(credentialOfferURI);
    }

    return CredentialOfferClient.fromURI(credentialOfferURI);
  }

  public static getOpenId4VCIVersion(uri: string): OpenId4VCIVersion {
    let version: OpenId4VCIVersion = OpenId4VCIVersion.VER_UNKNOWN;

    if (uri) {
      version = CredentialOfferUtil.getVersionFromScheme(uri, version);

      version = CredentialOfferUtil.getVersion(uri, OpenId4VCIVersion.VER_9, version, 'pre-authorized_code');
      version = CredentialOfferUtil.getVersion(uri, OpenId4VCIVersion.VER_11, version, 'credential_issuer');
      version = CredentialOfferUtil.getVersion(uri, OpenId4VCIVersion.VER_11, version, 'cryptographic_binding_methods_supported');
      version = CredentialOfferUtil.getVersion(uri, OpenId4VCIVersion.VER_11, version, 'cryptographic_suites_supported');
      version = CredentialOfferUtil.getVersion(uri, OpenId4VCIVersion.VER_11, version, 'credentialSubject');

      return version;
    }

    version = CredentialOfferUtil.recordVersion(version, OpenId4VCIVersion.VER_11, CredentialOfferUtil.getScheme(uri));

    return version;
  }

  public static getVersionFromScheme(credentialOfferURI: string, openId4VCIVersion: OpenId4VCIVersion) {
    const scheme = CredentialOfferUtil.getScheme(credentialOfferURI);
    if (credentialOfferURI.startsWith(DefaultURISchemes.CREDENTIAL_OFFER)) {
      return CredentialOfferUtil.recordVersion(openId4VCIVersion, OpenId4VCIVersion.VER_11, scheme);
    } else {
      return CredentialOfferUtil.recordVersion(openId4VCIVersion, OpenId4VCIVersion.VER_9, scheme);
    }
  }

  public static getScheme(credentialOfferURI: string) {
    return credentialOfferURI.split('?')[0];
  }

  public static getVersion(credentialOfferURI: string, expectedVersion: OpenId4VCIVersion, predeterminedVersion: OpenId4VCIVersion, param: string) {
    if (credentialOfferURI.includes(param)) {
      return CredentialOfferUtil.recordVersion(predeterminedVersion, expectedVersion, param);
    }
    return predeterminedVersion;
  }

  public static recordVersion(determinedVersion: OpenId4VCIVersion, potentialVersion: OpenId4VCIVersion, key: string) {
    if (determinedVersion === OpenId4VCIVersion.VER_UNKNOWN || determinedVersion === potentialVersion) {
      return potentialVersion;
    }

    throw new Error(`Invalid param. Some keys have been used from ${determinedVersion} version while '${key}' is used from ${potentialVersion}`);
  }
}
