import { Format } from '@sphereon/pex-models';

import {
  CommonSupportedMetadata,
  DiscoveryMetadataPayload,
  RPRegistrationMetadataPayload,
  SIOPErrors,
  SubjectSyntaxTypesSupportedValues,
} from '../types';

export function assertValidMetadata(opMetadata: DiscoveryMetadataPayload, rpMetadata: RPRegistrationMetadataPayload): CommonSupportedMetadata {
  let subjectSyntaxTypesSupported: string[] = [];
  const credentials = supportedCredentialsFormats(rpMetadata.vp_formats, opMetadata.vp_formats);
  const isValidSubjectSyntax = verifySubjectSyntaxes(rpMetadata.subject_syntax_types_supported);
  if (isValidSubjectSyntax && rpMetadata.subject_syntax_types_supported && opMetadata.subject_syntax_types_supported) {
    subjectSyntaxTypesSupported = supportedSubjectSyntaxTypes(rpMetadata.subject_syntax_types_supported, opMetadata.subject_syntax_types_supported);
  } else if (isValidSubjectSyntax && (!rpMetadata.subject_syntax_types_supported || !rpMetadata.subject_syntax_types_supported.length)) {
    if (opMetadata.subject_syntax_types_supported && Array.isArray(opMetadata.subject_syntax_types_supported)) {
      subjectSyntaxTypesSupported = [...opMetadata.subject_syntax_types_supported];
    }
  }
  return { vp_formats: credentials, subject_syntax_types_supported: subjectSyntaxTypesSupported };
}

function getIntersection<T>(rpMetadata: Array<T> | T, opMetadata: Array<T> | T): Array<T> {
  let arrayA, arrayB: Array<T>;
  if (!Array.isArray(rpMetadata)) {
    arrayA = [rpMetadata];
  } else {
    arrayA = rpMetadata;
  }
  if (!Array.isArray(opMetadata)) {
    arrayB = [opMetadata];
  } else {
    arrayB = opMetadata;
  }
  return arrayA.filter((value) => arrayB.includes(value));
}

function verifySubjectSyntaxes(subjectSyntaxTypesSupported?: string[]): boolean {
  if (subjectSyntaxTypesSupported && Array.isArray(subjectSyntaxTypesSupported)) {
    if (
      subjectSyntaxTypesSupported.length ===
      subjectSyntaxTypesSupported.filter(
        (sst) => sst.includes(SubjectSyntaxTypesSupportedValues.DID.valueOf()) || sst === SubjectSyntaxTypesSupportedValues.JWK_THUMBPRINT.valueOf(),
      ).length
    ) {
      return true;
    }
  }

  return false;
}

function supportedSubjectSyntaxTypes(rpMethods: string[] | string, opMethods: string[] | string): Array<string> {
  const rpMethodsList = Array.isArray(rpMethods) ? rpMethods : [rpMethods];
  const opMethodsList = Array.isArray(opMethods) ? opMethods : [opMethods];
  const supportedSubjectSyntaxTypes = getIntersection(rpMethodsList, opMethodsList);
  if (supportedSubjectSyntaxTypes.indexOf(SubjectSyntaxTypesSupportedValues.DID.valueOf()) !== -1) {
    return [SubjectSyntaxTypesSupportedValues.DID.valueOf()];
  }
  if (rpMethodsList.includes(SubjectSyntaxTypesSupportedValues.DID.valueOf())) {
    const supportedExtendedDids: string[] = opMethodsList.filter((method) => method.startsWith('did:'));
    if (supportedExtendedDids.length) {
      return supportedExtendedDids;
    }
  }
  if (opMethodsList.includes(SubjectSyntaxTypesSupportedValues.DID.valueOf())) {
    const supportedExtendedDids: string[] = rpMethodsList.filter((method) => method.startsWith('did:'));
    if (supportedExtendedDids.length) {
      return supportedExtendedDids;
    }
  }

  if (!supportedSubjectSyntaxTypes.length) {
    throw Error(SIOPErrors.DID_METHODS_NOT_SUPORTED);
  }
  const supportedDidMethods = supportedSubjectSyntaxTypes.filter((sst) => sst.includes('did:'));
  if (supportedDidMethods.length) {
    return supportedDidMethods;
  }
  return supportedSubjectSyntaxTypes;
}

function getFormatIntersection(rpFormat: Format, opFormat: Format): Format {
  const intersectionFormat: Format = {};
  const supportedCredentials = getIntersection(Object.keys(rpFormat), Object.keys(opFormat));
  if (!supportedCredentials.length) {
    throw new Error(SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED);
  }
  // FIXME: This looks buggy
  supportedCredentials.forEach((crFormat: string) => {
    const rpAlgs: string[] = [];
    const opAlgs: string[] = [];
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    Object.keys(rpFormat[crFormat]).forEach((k) => rpAlgs.push(...rpFormat[crFormat][k]));
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    Object.keys(opFormat[crFormat]).forEach((k) => opAlgs.push(...opFormat[crFormat][k]));
    let methodKeyRP = undefined;
    let methodKeyOP = undefined;
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    Object.keys(rpFormat[crFormat]).forEach((k) => (methodKeyRP = k));
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    Object.keys(opFormat[crFormat]).forEach((k) => (methodKeyOP = k));
    if (methodKeyRP !== methodKeyOP) {
      throw new Error(SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED);
    }
    const algs = getIntersection(rpAlgs, opAlgs);
    if (!algs.length) {
      throw new Error(SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED);
    }
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    intersectionFormat[crFormat] = {
      alg: algs,
    };
  });
  return intersectionFormat;
}

export function supportedCredentialsFormats(rpFormat: Format, opFormat: Format): Format {
  if (!rpFormat || !opFormat || !Object.keys(rpFormat).length || !Object.keys(opFormat).length) {
    throw new Error(SIOPErrors.CREDENTIALS_FORMATS_NOT_PROVIDED);
  }
  return getFormatIntersection(rpFormat, opFormat);
}
