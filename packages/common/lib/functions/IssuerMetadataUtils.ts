import {
  AuthorizationServerMetadata,
  CredentialIssuerMetadata,
  CredentialOfferFormat,
  CredentialSupported,
  CredentialSupportedTypeV1_0_08,
  CredentialSupportedV1_0_08,
  IssuerMetadataV1_0_08,
  MetadataDisplay,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
} from '../types';

export function getSupportedCredentials(opts?: {
  issuerMetadata?: CredentialIssuerMetadata | IssuerMetadataV1_0_08;
  version: OpenId4VCIVersion;
  types?: string[][];
  format?: (OID4VCICredentialFormat | string) | (OID4VCICredentialFormat | string)[];
}): CredentialSupported[] {
  if (opts?.types && Array.isArray(opts?.types)) {
    return opts.types.flatMap((types) => getSupportedCredential({ ...opts, types }));
  }
  return getSupportedCredential(opts ? { ...opts, types: undefined } : undefined);
}

export function getSupportedCredential(opts?: {
  issuerMetadata?: CredentialIssuerMetadata | IssuerMetadataV1_0_08;
  version: OpenId4VCIVersion;
  types?: string | string[];
  format?: (OID4VCICredentialFormat | string) | (OID4VCICredentialFormat | string)[];
}): CredentialSupported[] {
  const { issuerMetadata } = opts ?? {};
  let formats: (OID4VCICredentialFormat | string)[];
  if (opts?.format && Array.isArray(opts.format)) {
    formats = opts.format;
  } else if (opts?.format && !Array.isArray(opts.format)) {
    formats = [opts.format];
  } else {
    formats = [];
  }
  let credentialsSupported: CredentialSupported[];
  if (!issuerMetadata) {
    return [];
  }
  const { version, types } = opts ?? { version: OpenId4VCIVersion.VER_1_0_11 };
  if (version === OpenId4VCIVersion.VER_1_0_08 || !Array.isArray(issuerMetadata.credentials_supported)) {
    credentialsSupported = credentialsSupportedV8ToV11((issuerMetadata as IssuerMetadataV1_0_08).credentials_supported ?? {});
  } else {
    credentialsSupported = (issuerMetadata as CredentialIssuerMetadata).credentials_supported;
  }

  if (credentialsSupported === undefined || credentialsSupported.length === 0) {
    return [];
  } else if (!types || types.length === 0) {
    return credentialsSupported;
  }
  /**
   * the following (not array part is a legacy code from version 1_0-08 which JFF plugfest 2 implementors used)
   */
  let initiationTypes: string[] | undefined;
  if (opts?.types) {
    if (typeof opts.types === 'string') {
      initiationTypes = [opts.types];
    } else {
      initiationTypes = opts.types;
    }
  }
  if (version === OpenId4VCIVersion.VER_1_0_08 && (!initiationTypes || initiationTypes?.length === 0)) {
    initiationTypes = formats;
  }
  const supportedFormats: (CredentialOfferFormat | string)[] = formats && formats.length > 0 ? formats : ['jwt_vc_json', 'jwt_vc_json-ld', 'ldp_vc'];

  const credentialSupportedOverlap: CredentialSupported[] = [];
  if ((opts?.types && typeof opts?.types === 'string') || opts?.types?.length === 1) {
    const types = Array.isArray(opts.types) ? opts.types[0] : opts.types;
    const supported = credentialsSupported.filter(
      (sup) => sup.id === types || (initiationTypes && arrayEqualsIgnoreOrder(getTypesFromCredentialSupported(sup), initiationTypes)),
    );
    if (supported) {
      credentialSupportedOverlap.push(...supported);
    }
  }

  if (credentialSupportedOverlap.length === 0) {
    // Make sure we include Verifiable Credential both on the offer side as well as in the metadata side, to ensure consistency of the issuer does not.
    if (initiationTypes && !initiationTypes.includes('VerifiableCredential')) {
      initiationTypes.push('VerifiableCredential');
    }
    const supported = credentialsSupported.filter((sup) => {
      const supTypes = getTypesFromCredentialSupported(sup);
      if (!supTypes.includes('VerifiableCredential')) {
        supTypes.push('VerifiableCredential');
      }
      return (!initiationTypes || arrayEqualsIgnoreOrder(supTypes, initiationTypes)) && supportedFormats.includes(sup.format);
    });
    if (supported) {
      credentialSupportedOverlap.push(...supported);
    }
  }
  return credentialSupportedOverlap;
}

export function getTypesFromCredentialSupported(credentialSupported: CredentialSupported, opts?: { filterVerifiableCredential: boolean }) {
  let types: string[] = [];
  if (
    credentialSupported.format === 'jwt_vc_json' ||
    credentialSupported.format === 'jwt_vc' ||
    credentialSupported.format === 'jwt_vc_json-ld' ||
    credentialSupported.format === 'ldp_vc'
  ) {
    types = credentialSupported.types;
  } else if (credentialSupported.format === 'vc+sd-jwt') {
    types = [credentialSupported.vct];
  }

  if (!types || types.length === 0) {
    throw Error('Could not deduce types from credential supported');
  }
  if (opts?.filterVerifiableCredential) {
    return types.filter((type) => type !== 'VerifiableCredential');
  }
  return types;
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
      format: format as OID4VCICredentialFormat,
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
      (item) => !opts?.prefLocales || opts.prefLocales.length === 0 || (item.locale && opts.prefLocales.includes(item.locale)) || !item.locale,
    ) ?? [];
  return matchedDisplays.sort((item) => (item.locale ? opts?.prefLocales.indexOf(item.locale) ?? 1 : Number.MAX_VALUE));
}

/**
 * TODO check again when WAL-617 is done to replace how we get the issuer name.
 */
export function getIssuerName(
  url: string,
  credentialIssuerMetadata?: Partial<AuthorizationServerMetadata> & (CredentialIssuerMetadata | IssuerMetadataV1_0_08),
): string {
  if (credentialIssuerMetadata) {
    const displays: Array<MetadataDisplay> = credentialIssuerMetadata ? getIssuerDisplays(credentialIssuerMetadata) : [];
    for (const display of displays) {
      if (display.name) {
        return display.name;
      }
    }
  }
  return url;
}
