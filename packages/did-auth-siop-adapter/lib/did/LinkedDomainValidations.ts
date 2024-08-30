import { IDomainLinkageValidation, ValidationStatusEnum, VerifyCallback, WDCErrors, WellKnownDidVerifier } from '@sphereon/wellknown-dids-client'

import { DIDDocument } from '../types/SSI.types'

import { CheckLinkedDomain, ExternalVerification, InternalVerification } from './../types/'
import { resolveDidDocument } from './DIDResolution'
import { getMethodFromDid, toSIOPRegistrationDidMethod } from './DidJWT'

function getValidationErrorMessages(validationResult: IDomainLinkageValidation): string[] {
  const messages = []
  if (validationResult.message) {
    messages.push(validationResult.message)
  }
  if (validationResult?.endpointDescriptors?.length) {
    for (const endpointDescriptor of validationResult.endpointDescriptors) {
      if (endpointDescriptor.message) {
        messages.push(endpointDescriptor.message)
      }
      if (endpointDescriptor.resources) {
        for (const resource of endpointDescriptor.resources) {
          if (resource.message) {
            messages.push(resource.message)
          }
        }
      }
    }
  }
  return messages
}

/**
 * @param validationErrorMessages
 * @return returns false if the messages received from wellknown-dids-client makes this invalid for CheckLinkedDomain.IF_PRESENT plus the message itself
 *                  and true for when we can move on
 */
function checkInvalidMessages(validationErrorMessages: string[]): { status: boolean; message?: string } {
  if (!validationErrorMessages || !validationErrorMessages.length) {
    return { status: false, message: 'linked domain is invalid.' }
  }
  const validMessages: string[] = [
    WDCErrors.PROPERTY_LINKED_DIDS_DOES_NOT_CONTAIN_ANY_DOMAIN_LINK_CREDENTIALS.valueOf(),
    WDCErrors.PROPERTY_LINKED_DIDS_NOT_PRESENT.valueOf(),
    WDCErrors.PROPERTY_TYPE_NOT_CONTAIN_VALID_LINKED_DOMAIN.valueOf(),
    WDCErrors.PROPERTY_SERVICE_NOT_PRESENT.valueOf(),
  ]
  for (const validationErrorMessage of validationErrorMessages) {
    if (!validMessages.filter((vm) => validationErrorMessage.includes(vm)).pop()) {
      return { status: false, message: validationErrorMessage }
    }
  }
  return { status: true }
}

export async function validateLinkedDomainWithDid(did: string, verification: InternalVerification | ExternalVerification): Promise<void> {
  const { checkLinkedDomain, resolveOpts, wellknownDIDVerifyCallback } = verification
  if (checkLinkedDomain === CheckLinkedDomain.NEVER) {
    return
  }
  const didDocument = await resolveDidDocument(did, {
    ...resolveOpts,
    subjectSyntaxTypesSupported: [toSIOPRegistrationDidMethod(getMethodFromDid(did))],
  })
  if (!didDocument) {
    throw Error(`Could not resolve DID: ${did}`)
  }
  if ((!didDocument.service || !didDocument.service.find((s) => s.type === 'LinkedDomains')) && checkLinkedDomain === CheckLinkedDomain.IF_PRESENT) {
    // No linked domains in DID document and it was optional. Let's cut it short here.
    return
  }
  try {
    if (!wellknownDIDVerifyCallback) {
      return Promise.reject(Error('wellknownDIDVerifyCallback is required for checkWellKnownDid'))
    }
    const validationResult = await checkWellKnownDid({ didDocument, verifyCallback: wellknownDIDVerifyCallback })
    if (validationResult.status === ValidationStatusEnum.INVALID) {
      const validationErrorMessages = getValidationErrorMessages(validationResult)
      const messageCondition: { status: boolean; message?: string } = checkInvalidMessages(validationErrorMessages)
      if (checkLinkedDomain === CheckLinkedDomain.ALWAYS || (checkLinkedDomain === CheckLinkedDomain.IF_PRESENT && !messageCondition.status)) {
        throw new Error(messageCondition.message ? messageCondition.message : validationErrorMessages[0])
      }
    }
  } catch (err: any) {
    const messageCondition: { status: boolean; message?: string } = checkInvalidMessages([err.message])
    if (checkLinkedDomain === CheckLinkedDomain.ALWAYS || (checkLinkedDomain === CheckLinkedDomain.IF_PRESENT && !messageCondition.status)) {
      throw new Error(err.message)
    }
  }
}

interface CheckWellKnownDidArgs {
  didDocument: DIDDocument
  verifyCallback: VerifyCallback
}

async function checkWellKnownDid(args: CheckWellKnownDidArgs): Promise<IDomainLinkageValidation> {
  const verifier = new WellKnownDidVerifier({
    verifySignatureCallback: args.verifyCallback,
    onlyVerifyServiceDid: false,
  })
  return await verifier.verifyDomainLinkage({ didDocument: args.didDocument })
}
