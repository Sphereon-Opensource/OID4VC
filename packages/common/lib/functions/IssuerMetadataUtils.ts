import {
  CredentialIssuerMetadata,
  CredentialOfferFormat,
  CredentialSupported,
  MetadataDisplay,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
} from '../types';

export function getSupportedCredentials(opts?: {
  issuerMetadata?: CredentialIssuerMetadata;
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
  issuerMetadata?: CredentialIssuerMetadata;
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

  if (!issuerMetadata) {
    return [];
  }
  const { types } = opts ?? {};
  const credentialsSupported: CredentialSupported[] = (issuerMetadata as CredentialIssuerMetadata).credentials_supported;

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
  if (credentialSupported.format !== 'vc+sd-jwt') {
      credentialSupported.format === 'jwt_vc_json' ||
      credentialSupported.format === 'jwt_vc' ||
      credentialSupported.format === 'jwt_vc_json-ld' ||
      credentialSupported.format === 'ldp_vc'
      types = credentialSupported.credential_definition.type;
  } else {
    types = [credentialSupported.credential_definition.vct];
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


export function getIssuerDisplays(metadata: CredentialIssuerMetadata, opts?: { prefLocales: string[] }): MetadataDisplay[] {
  const matchedDisplays =
    metadata.display?.filter(
      (item) => !opts?.prefLocales || opts.prefLocales.length === 0 || (item.locale && opts.prefLocales.includes(item.locale)) || !item.locale,
    ) ?? [];
  return matchedDisplays.sort((item) => (item.locale ? opts?.prefLocales.indexOf(item.locale) ?? 1 : Number.MAX_VALUE));
}
