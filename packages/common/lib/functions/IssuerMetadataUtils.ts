import {
  CredentialIssuerMetadata,
  CredentialOfferFormat,
  CredentialSupported,
  CredentialSupportedTypeV1_0_08,
  CredentialSupportedV1_0_08,
  IssuerMetadataV1_0_08,
  MetadataDisplay,
  OpenId4VCIVersion,
} from '../types';

export function getSupportedCredentials(opts?: {
  issuerMetadata?: CredentialIssuerMetadata | IssuerMetadataV1_0_08;
  version: OpenId4VCIVersion;
  credentialTypes?: (CredentialOfferFormat | string)[];
  supportedType?: CredentialOfferFormat | string;
}): CredentialSupported[] {
  const { issuerMetadata } = opts ?? {};
  let credentialsSupported: CredentialSupported[];
  if (!issuerMetadata) {
    return [];
  }
  const { version, credentialTypes, supportedType } = opts ?? { version: OpenId4VCIVersion.VER_1_0_11 };
  if (version === OpenId4VCIVersion.VER_1_0_08 || !Array.isArray(issuerMetadata.credentials_supported)) {
    credentialsSupported = credentialsSupportedV8ToV11((issuerMetadata as IssuerMetadataV1_0_08).credentials_supported);
    /*    const credentialsSupportedV8: CredentialSupportedV1_0_08 = credentialsSupported as CredentialSupportedV1_0_08
        // const initiationTypes = credentialTypes.map(type => typeof type === 'string' ? [type] : type.types)
        const supported: IssuerCredentialSubject = {}
        for (const [key, value] of Object.entries(credentialsSupportedV8)) {
          if (initiationTypes.find((type) => (typeof type === 'string' ? type === key : type.types.includes(key)))) {
            supported[key] = value
          }
        }
        // todo: fix this later. we're returning CredentialSupportedV1_0_08 as a list of CredentialSupported (for v09 onward)
        return supported as unknown as CredentialSupported[]*/
  } else {
    credentialsSupported = (issuerMetadata as CredentialIssuerMetadata).credentials_supported;
  }

  if (credentialsSupported === undefined || credentialsSupported.length === 0) {
    return [];
  } else if (!credentialTypes || credentialTypes.length === 0) {
    return credentialsSupported;
  }
  /**
   * the following (not array part is a legacy code from version 1_0-08 which JFF plugfest 2 implementors used)
   */
  const initiationTypes = supportedType ? [supportedType] : credentialTypes;

  const credentialSupportedOverlap: CredentialSupported[] = [];
  for (const offerType of initiationTypes) {
    if (typeof offerType === 'string') {
      const supported = credentialsSupported.filter((sup) => sup.id === offerType || sup.types.includes(offerType));
      if (supported) {
        credentialSupportedOverlap.push(...supported);
      }
    } else {
      const supported = credentialsSupported.filter((sup) => arrayEqualsIgnoreOrder(sup.types, offerType.types) && sup.format === offerType.format);
      if (supported) {
        credentialSupportedOverlap.push(...supported);
      }
    }
  }
  return credentialSupportedOverlap;
}

function arrayEqualsIgnoreOrder(a: string[], b: string[]) {
  if (a.length !== b.length) return false;
  const uniqueValues = new Set([...a, ...b]);
  for (const v of uniqueValues) {
    const aCount = a.filter((e) => e === v).length;
    const bCount = b.filter((e) => e === v).length;
    if (aCount !== bCount) return false;
  }
  return true;
}

export function credentialsSupportedV8ToV11(supportedV8: CredentialSupportedTypeV1_0_08): CredentialSupported[] {
  return Object.entries(supportedV8).flatMap((entry) => {
    const type = entry[0];
    const supportedV8 = entry[1];
    return credentialSupportedV8ToV11(type, supportedV8);
  });
}

export function credentialSupportedV8ToV11(key: string, supportedV8: CredentialSupportedV1_0_08): CredentialSupported[] {
  return Object.entries(supportedV8.formats).map((entry) => {
    const format = entry[0];
    const credentialSupportBrief = entry[1];
    if (typeof format !== 'string') {
      throw Error(`Unknown format received ${JSON.stringify(format)}`);
    }
    let credentialSupport: Partial<CredentialSupported> = {};
    credentialSupport = {
      format,
      display: supportedV8.display,
      ...credentialSupportBrief,
      credentialSubject: supportedV8.claims,
    };
    return credentialSupport as CredentialSupported;
  });
}

export function getIssuerDisplays(metadata: CredentialIssuerMetadata | IssuerMetadataV1_0_08, opts?: { prefLocales: string[] }): MetadataDisplay[] {
  const matchedDisplays =
    metadata.display?.filter(
      (item) => !opts?.prefLocales || opts.prefLocales.length === 0 || (item.locale && opts.prefLocales.includes(item.locale)) || !item.locale
    ) ?? [];
  return matchedDisplays.sort((item) => (item.locale ? opts?.prefLocales.indexOf(item.locale) ?? 1 : Number.MAX_VALUE));
}
