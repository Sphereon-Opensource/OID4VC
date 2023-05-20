import { CredentialIssuerMetadata, CredentialOfferFormat, CredentialSupported, CredentialSupportedV1_0_08, IssuerCredentialSubject } from '../types';

export function getCredentialsSupported(
  issuerMetadata: CredentialIssuerMetadata,
  credentialTypes?: (CredentialOfferFormat | string)[],
  supportedType?: CredentialOfferFormat | string
): CredentialSupported[] {
  const credentialsSupported = issuerMetadata?.credentials_supported;
  if (!credentialsSupported) {
    return [];
  } else if (!credentialTypes || credentialTypes.length === 0) {
    return credentialsSupported;
  }
  /**
   * the following (not array part is a legacy code from version 1_0-08 which JFF plugfest 2 implementors used)
   */
  const initiationTypes = supportedType ? [supportedType] : credentialTypes;
  if (!Array.isArray(credentialsSupported)) {
    const credentialsSupportedV8: CredentialSupportedV1_0_08 = credentialsSupported as CredentialSupportedV1_0_08;
    // const initiationTypes = credentialTypes.map(type => typeof type === 'string' ? [type] : type.types)
    const supported: IssuerCredentialSubject = {};
    for (const [key, value] of Object.entries(credentialsSupportedV8)) {
      if (initiationTypes.find((type) => (typeof type === 'string' ? type === key : type.types.includes(key)))) {
        supported[key] = value;
      }
    }
    // todo: fix this later. we're returning CredentialSupportedV1_0_08 as a list of CredentialSupported (for v09 onward)
    return supported as unknown as CredentialSupported[];
  }

  const credentialSupportedOverlap: CredentialSupported[] = [];
  for (const offerType of initiationTypes) {
    if (typeof offerType === 'string') {
      const supported = credentialsSupported.find((sup) => sup.id === offerType);
      if (supported) {
        credentialSupportedOverlap.push(supported);
      }
    } else {
      const supported = credentialsSupported.find((sup) => sup.types == offerType.types && sup.format === offerType.format);
      if (supported) {
        credentialSupportedOverlap.push(supported);
      }
    }
  }
  return credentialSupportedOverlap as CredentialSupported[];
}
