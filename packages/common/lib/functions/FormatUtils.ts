import { CredentialFormat } from '@sphereon/ssi-types';

import { OID4VCICredentialFormat, OpenId4VCIVersion } from '../types';

export function isFormat<T extends { format?: OID4VCICredentialFormat }, Format extends OID4VCICredentialFormat>(
  formatObject: T,
  format: Format,
): formatObject is T & { format: Format } {
  return formatObject.format === format;
}

export function isNotFormat<T extends { format?: OID4VCICredentialFormat }, Format extends OID4VCICredentialFormat>(
  formatObject: T,
  format: Format,
): formatObject is T & { format: Exclude<OID4VCICredentialFormat, Format> } {
  return formatObject.format !== format;
}

const isUniformFormat = (format: string): format is OID4VCICredentialFormat => {
  return ['jwt_vc_json', 'jwt_vc_json-ld', 'ldp_vc', 'vc+sd-jwt'].includes(format);
};

export function getUniformFormat(format: string | OID4VCICredentialFormat | CredentialFormat): OID4VCICredentialFormat {
  // Already valid format
  if (isUniformFormat(format)) {
    return format;
  }

  // Older formats
  if (format === 'jwt_vc' || format === 'jwt') {
    return 'jwt_vc';
  }
  if (format === 'ldp_vc' || format === 'ldp') {
    return 'ldp_vc';
  }

  throw new Error(`Invalid format: ${format}`);
}

export function getFormatForVersion(format: string, version: OpenId4VCIVersion) {
  return isUniformFormat(format) ? format : getUniformFormat(format);
}
