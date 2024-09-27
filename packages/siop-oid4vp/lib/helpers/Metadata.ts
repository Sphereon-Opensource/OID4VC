import { Format } from '@sphereon/pex-models'

import {
  CommonSupportedMetadata,
  DiscoveryMetadataPayload,
  RPRegistrationMetadataPayload,
  SIOPErrors,
  SubjectSyntaxTypesSupportedValues,
} from '../types'

export function assertValidMetadata(opMetadata: DiscoveryMetadataPayload, rpMetadata: RPRegistrationMetadataPayload): CommonSupportedMetadata {
  let subjectSyntaxTypesSupported: string[] = []
  const credentials = supportedCredentialsFormats(rpMetadata.vp_formats, opMetadata.vp_formats)
  const isValidSubjectSyntax = verifySubjectSyntaxes(rpMetadata.subject_syntax_types_supported)
  if (isValidSubjectSyntax && rpMetadata.subject_syntax_types_supported) {
    subjectSyntaxTypesSupported = supportedSubjectSyntaxTypes(rpMetadata.subject_syntax_types_supported, opMetadata.subject_syntax_types_supported as string[])
  } else if (isValidSubjectSyntax && (!rpMetadata.subject_syntax_types_supported || !rpMetadata.subject_syntax_types_supported.length)) {
    if (opMetadata.subject_syntax_types_supported) {
      subjectSyntaxTypesSupported = [...opMetadata.subject_syntax_types_supported]
    }
  }
  return { vp_formats: credentials, subject_syntax_types_supported: subjectSyntaxTypesSupported }
}

function getIntersection<T>(rpMetadata: Array<T> | T, opMetadata: Array<T> | T): Array<T> {
  let arrayA, arrayB
  if (!Array.isArray(rpMetadata)) {
    arrayA = [rpMetadata]
  } else {
    arrayA = rpMetadata
  }
  if (!Array.isArray(opMetadata)) {
    arrayB = [opMetadata]
  } else {
    arrayB = opMetadata
  }
  return arrayA.filter((value) => arrayB.includes(value))
}

function verifySubjectSyntaxes(subjectSyntaxTypesSupported: string[] | undefined): boolean {
  if (subjectSyntaxTypesSupported?.length) {
    if (Array.isArray(subjectSyntaxTypesSupported)) {
      if (
        subjectSyntaxTypesSupported.length ===
        subjectSyntaxTypesSupported.filter(
          (sst) =>
            sst.includes(SubjectSyntaxTypesSupportedValues.DID.valueOf()) || sst === SubjectSyntaxTypesSupportedValues.JWK_THUMBPRINT.valueOf(),
        ).length
      ) {
        return true
      }
    }
  }
  return false
}

function supportedSubjectSyntaxTypes(rpMethods: string[] | string, opMethods: string[] | string): Array<string> {
  const rpMethodsList = Array.isArray(rpMethods) ? rpMethods : [rpMethods]
  const opMethodsList = Array.isArray(opMethods) ? opMethods : [opMethods]
  const supportedSubjectSyntaxTypes = getIntersection(rpMethodsList, opMethodsList)
  if (supportedSubjectSyntaxTypes.indexOf(SubjectSyntaxTypesSupportedValues.DID.valueOf()) !== -1) {
    return [SubjectSyntaxTypesSupportedValues.DID.valueOf()]
  }
  if (rpMethodsList.includes(SubjectSyntaxTypesSupportedValues.DID.valueOf())) {
    const supportedExtendedDids: string[] = opMethodsList.filter((method) => method.startsWith('did:'))
    if (supportedExtendedDids.length) {
      return supportedExtendedDids
    }
  }
  if (opMethodsList.includes(SubjectSyntaxTypesSupportedValues.DID.valueOf())) {
    const supportedExtendedDids: string[] = rpMethodsList.filter((method) => method.startsWith('did:'))
    if (supportedExtendedDids.length) {
      return supportedExtendedDids
    }
  }

  if (!supportedSubjectSyntaxTypes.length) {
    throw Error(SIOPErrors.DID_METHODS_NOT_SUPORTED)
  }
  const supportedDidMethods = supportedSubjectSyntaxTypes.filter((sst) => sst.includes('did:'))
  if (supportedDidMethods.length) {
    return supportedDidMethods
  }
  return supportedSubjectSyntaxTypes
}

export function collectAlgValues(o: any): string[] {
  const algValues: string[] = [];
  for (const key of Object.keys(o)) {
    algValues.push(...o[key]);
  }

  return algValues;
}

const isJwtFormat = (crFormat: string) => crFormat.includes('jwt') || crFormat.includes('mdoc');

function getFormatIntersection(rpFormat: Format, opFormat: Format): Format {
  const intersectionFormat: Record<string, any> = {}
  const supportedCredentials = getIntersection(Object.keys(rpFormat), Object.keys(opFormat))
  if (!supportedCredentials.length) {
    throw new Error(SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED)
  }
  supportedCredentials.forEach(function (crFormat: string) {
    const rpFormatElement = rpFormat[crFormat as keyof Format];
    const opFormatElement = opFormat[crFormat as keyof Format];
    const rpAlgs = collectAlgValues(rpFormatElement);
    const opAlgs = collectAlgValues(opFormatElement);
    let methodKeyRP = undefined;
    let methodKeyOP = undefined;
    if (rpFormatElement !== undefined) {
      Object.keys(rpFormatElement).forEach((k) => (methodKeyRP = k));
    }
    if (opFormatElement !== undefined) {
      Object.keys(opFormatElement).forEach((k) => (methodKeyOP = k));
    }
    if (methodKeyRP !== methodKeyOP) {
      throw new Error(SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED)
    }
    const algs = getIntersection(rpAlgs, opAlgs)
    if (!algs.length && isJwtFormat(crFormat)) {
      throw new Error(SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED)
    }
    intersectionFormat[crFormat] = {}
    if(methodKeyOP !== undefined) {
      intersectionFormat[crFormat][methodKeyOP] = algs
    }
  })
  return intersectionFormat
}

export function supportedCredentialsFormats(rpFormat: Format, opFormat: Format): Format {
  if (!rpFormat || !opFormat || !Object.keys(rpFormat).length || !Object.keys(opFormat).length) {
    throw new Error(SIOPErrors.CREDENTIALS_FORMATS_NOT_PROVIDED)
  }
  return getFormatIntersection(rpFormat, opFormat)
}
