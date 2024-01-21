import {
  EvaluationResults,
  IPresentationDefinition,
  KeyEncoding,
  PEX,
  PresentationSubmissionLocation,
  SelectResults,
  Status,
  VerifiablePresentationFromOpts,
  VerifiablePresentationResult,
} from '@sphereon/pex';
import { Format, PresentationDefinitionV1, PresentationDefinitionV2, PresentationSubmission } from '@sphereon/pex-models';
import {
  CredentialMapper,
  Hasher,
  IProofPurpose,
  IProofType,
  OriginalVerifiableCredential,
  OriginalVerifiablePresentation,
  W3CVerifiablePresentation,
  WrappedVerifiablePresentation,
} from '@sphereon/ssi-types';

import { extractDataFromPath, getWithUrl } from '../helpers';
import { AuthorizationRequestPayload, SIOPErrors, SupportedVersion } from '../types';

import {
  PresentationDefinitionLocation,
  PresentationDefinitionWithLocation,
  PresentationSignCallback,
  PresentationVerificationCallback,
} from './types';

export class PresentationExchange {
  readonly pex: PEX;
  readonly allVerifiableCredentials: OriginalVerifiableCredential[];
  readonly allDIDs;

  constructor(opts: { allDIDs?: string[]; allVerifiableCredentials: OriginalVerifiableCredential[]; hasher?: Hasher }) {
    this.allDIDs = opts.allDIDs;
    this.allVerifiableCredentials = opts.allVerifiableCredentials;
    this.pex = new PEX({ hasher: opts.hasher });
  }

  /**
   * Construct presentation submission from selected credentials
   * @param presentationDefinition payload object received by the OP from the RP
   * @param selectedCredentials
   * @param presentationSignCallback
   * @param options
   */
  public async createVerifiablePresentation(
    presentationDefinition: IPresentationDefinition,
    selectedCredentials: OriginalVerifiableCredential[],
    presentationSignCallback: PresentationSignCallback,
    // options2?: { nonce?: string; domain?: string, proofType?: IProofType, verificationMethod?: string, signatureKeyEncoding?: KeyEncoding },
    options?: VerifiablePresentationFromOpts,
  ): Promise<VerifiablePresentationResult> {
    if (!presentationDefinition) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    }

    const signOptions: VerifiablePresentationFromOpts = {
      ...options,
      presentationSubmissionLocation: PresentationSubmissionLocation.EXTERNAL,
      proofOptions: {
        ...options.proofOptions,
        proofPurpose: options?.proofOptions?.proofPurpose ?? IProofPurpose.authentication,
        type: options?.proofOptions?.type ?? IProofType.EcdsaSecp256k1Signature2019,
        /* challenge: options?.proofOptions?.challenge,
        domain: options?.proofOptions?.domain,*/
      },
      signatureOptions: {
        ...options.signatureOptions,
        // verificationMethod: options?.signatureOptions?.verificationMethod,
        keyEncoding: options?.signatureOptions?.keyEncoding ?? KeyEncoding.Hex,
      },
    };

    return await this.pex.verifiablePresentationFrom(presentationDefinition, selectedCredentials, presentationSignCallback, signOptions);
  }

  /**
   * This method will be called from the OP when we are certain that we have a
   * PresentationDefinition object inside our requestPayload
   * Finds a set of `VerifiableCredential`s from a list supplied to this class during construction,
   * matching presentationDefinition object found in the requestPayload
   * if requestPayload doesn't contain any valid presentationDefinition throws an error
   * if PEX library returns any error in the process, throws the error
   * returns the SelectResults object if successful
   * @param presentationDefinition object received by the OP from the RP
   * @param opts
   */
  public async selectVerifiableCredentialsForSubmission(
    presentationDefinition: IPresentationDefinition,
    opts?: {
      holderDIDs?: string[];
      restrictToFormats?: Format;
      restrictToDIDMethods?: string[];
    },
  ): Promise<SelectResults> {
    if (!presentationDefinition) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    } else if (!this.allVerifiableCredentials || this.allVerifiableCredentials.length == 0) {
      throw new Error(`${SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, no VCs were provided`);
    }
    const selectResults: SelectResults = this.pex.selectFrom(presentationDefinition, this.allVerifiableCredentials, {
      ...opts,
      holderDIDs: opts?.holderDIDs ?? this.allDIDs,
      // fixme limited disclosure
      limitDisclosureSignatureSuites: [],
    });
    if (selectResults.areRequiredCredentialsPresent === Status.ERROR) {
      throw new Error(`message: ${SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, details: ${JSON.stringify(selectResults.errors)}`);
    }
    return selectResults;
  }

  /**
   * validatePresentationAgainstDefinition function is called mainly by the RP
   * after receiving the VP from the OP
   * @param presentationDefinition object containing PD
   * @param verifiablePresentation
   * @param opts
   */
  public static async validatePresentationAgainstDefinition(
    presentationDefinition: IPresentationDefinition,
    verifiablePresentation: OriginalVerifiablePresentation | WrappedVerifiablePresentation,
    opts?: {
      limitDisclosureSignatureSuites?: string[];
      restrictToFormats?: Format;
      restrictToDIDMethods?: string[];
      presentationSubmission?: PresentationSubmission;
      hasher?: Hasher;
    },
  ): Promise<EvaluationResults> {
    const wvp: WrappedVerifiablePresentation =
      typeof verifiablePresentation === 'object' && 'original' in verifiablePresentation
        ? (verifiablePresentation as WrappedVerifiablePresentation)
        : CredentialMapper.toWrappedVerifiablePresentation(verifiablePresentation as OriginalVerifiablePresentation);
    if (!presentationDefinition) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    } else if (
      !wvp ||
      !wvp.presentation ||
      (CredentialMapper.isWrappedW3CVerifiablePresentation(wvp) &&
        (!wvp.presentation.verifiableCredential || wvp.presentation.verifiableCredential.length === 0))
    ) {
      throw new Error(SIOPErrors.NO_VERIFIABLE_PRESENTATION_NO_CREDENTIALS);
    }
    // console.log(`Presentation (validate): ${JSON.stringify(verifiablePresentation)}`);
    const evaluationResults: EvaluationResults = new PEX({ hasher: opts?.hasher }).evaluatePresentation(presentationDefinition, wvp.original, opts);
    if (evaluationResults.errors.length) {
      throw new Error(`message: ${SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, details: ${JSON.stringify(evaluationResults.errors)}`);
    }
    return evaluationResults;
  }

  public static assertValidPresentationSubmission(presentationSubmission: PresentationSubmission) {
    const validationResult = PEX.validateSubmission(presentationSubmission);
    if (validationResult[0].message != 'ok') {
      throw new Error(`${SIOPErrors.RESPONSE_OPTS_PRESENTATIONS_SUBMISSION_IS_NOT_VALID}, details ${JSON.stringify(validationResult[0])}`);
    }
  }

  /**
   * Finds a valid PresentationDefinition inside the given AuthenticationRequestPayload
   * throws exception if the PresentationDefinition is not valid
   * returns null if no property named "presentation_definition" is found
   * returns a PresentationDefinition if a valid instance found
   * @param authorizationRequestPayload object that can have a presentation_definition inside
   * @param version
   */
  public static async findValidPresentationDefinitions(
    authorizationRequestPayload: AuthorizationRequestPayload,
    version?: SupportedVersion,
  ): Promise<PresentationDefinitionWithLocation[]> {
    const allDefinitions: PresentationDefinitionWithLocation[] = [];

    async function extractDefinitionFromVPToken() {
      const vpTokens: PresentationDefinitionV1[] | PresentationDefinitionV2[] = extractDataFromPath(
        authorizationRequestPayload,
        '$..vp_token.presentation_definition',
      ).map((d) => d.value);
      const vpTokenRefs = extractDataFromPath(authorizationRequestPayload, '$..vp_token.presentation_definition_uri');
      if (vpTokens && vpTokens.length && vpTokenRefs && vpTokenRefs.length) {
        throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_BY_REF_AND_VALUE_NON_EXCLUSIVE);
      }
      if (vpTokens && vpTokens.length) {
        vpTokens.forEach((vpToken: PresentationDefinitionV1 | PresentationDefinitionV2) => {
          if (allDefinitions.find((value) => value.definition.id === vpToken.id)) {
            console.log(
              `Warning. We encountered presentation definition with id ${vpToken.id}, more then once whilst processing! Make sure your payload is valid!`,
            );
            return;
          }
          PresentationExchange.assertValidPresentationDefinition(vpToken);
          allDefinitions.push({
            definition: vpToken,
            location: PresentationDefinitionLocation.CLAIMS_VP_TOKEN,
            version,
          });
        });
      } else if (vpTokenRefs && vpTokenRefs.length) {
        for (const vpTokenRef of vpTokenRefs) {
          const pd: PresentationDefinitionV1 | PresentationDefinitionV2 = (await getWithUrl(vpTokenRef.value)) as unknown as
            | PresentationDefinitionV1
            | PresentationDefinitionV2;
          if (allDefinitions.find((value) => value.definition.id === pd.id)) {
            console.log(
              `Warning. We encountered presentation definition with id ${pd.id}, more then once whilst processing! Make sure your payload is valid!`,
            );
            return;
          }
          PresentationExchange.assertValidPresentationDefinition(pd);
          allDefinitions.push({ definition: pd, location: PresentationDefinitionLocation.CLAIMS_VP_TOKEN, version });
        }
      }
    }

    function addSingleToplevelPDToPDs(definition: IPresentationDefinition, version?: SupportedVersion): void {
      if (allDefinitions.find((value) => value.definition.id === definition.id)) {
        console.log(
          `Warning. We encountered presentation definition with id ${definition.id}, more then once whilst processing! Make sure your payload is valid!`,
        );
        return;
      }
      PresentationExchange.assertValidPresentationDefinition(definition);
      allDefinitions.push({
        definition,
        location: PresentationDefinitionLocation.TOPLEVEL_PRESENTATION_DEF,
        version,
      });
    }

    async function extractDefinitionFromTopLevelDefinitionProperty(version?: SupportedVersion) {
      const definitions = extractDataFromPath(authorizationRequestPayload, '$.presentation_definition');
      const definitionsFromList = extractDataFromPath(authorizationRequestPayload, '$.presentation_definition[*]');
      const definitionRefs = extractDataFromPath(authorizationRequestPayload, '$.presentation_definition_uri');
      const definitionRefsFromList = extractDataFromPath(authorizationRequestPayload, '$.presentation_definition_uri[*]');
      const hasPD = (definitions && definitions.length > 0) || (definitionsFromList && definitionsFromList.length > 0);
      const hasPdRef = (definitionRefs && definitionRefs.length > 0) || (definitionRefsFromList && definitionRefsFromList.length > 0);
      if (hasPD && hasPdRef) {
        throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_BY_REF_AND_VALUE_NON_EXCLUSIVE);
      }
      if (definitions && definitions.length > 0) {
        definitions.forEach((definition) => {
          addSingleToplevelPDToPDs(definition.value, version);
        });
      } else if (definitionsFromList && definitionsFromList.length > 0) {
        definitionsFromList.forEach((definition) => {
          addSingleToplevelPDToPDs(definition.value, version);
        });
      } else if (definitionRefs && definitionRefs.length > 0) {
        for (const definitionRef of definitionRefs) {
          const pd: PresentationDefinitionV1 | PresentationDefinitionV2 = await getWithUrl(definitionRef.value);
          addSingleToplevelPDToPDs(pd, version);
        }
      } else if (definitionsFromList && definitionRefsFromList.length > 0) {
        for (const definitionRef of definitionRefsFromList) {
          const pd: PresentationDefinitionV1 | PresentationDefinitionV2 = await getWithUrl(definitionRef.value);
          addSingleToplevelPDToPDs(pd, version);
        }
      }
    }

    if (authorizationRequestPayload) {
      if (!version || version < SupportedVersion.SIOPv2_D11) {
        await extractDefinitionFromVPToken();
      }
      await extractDefinitionFromTopLevelDefinitionProperty();
    }
    return allDefinitions;
  }

  public static assertValidPresentationDefinitionWithLocations(definitionsWithLocations: PresentationDefinitionWithLocation[]) {
    if (definitionsWithLocations && definitionsWithLocations.length > 0) {
      definitionsWithLocations.forEach((definitionWithLocation) =>
        PresentationExchange.assertValidPresentationDefinition(definitionWithLocation.definition),
      );
    }
  }

  private static assertValidPresentationDefinition(presentationDefinition: IPresentationDefinition) {
    const validationResult = PEX.validateDefinition(presentationDefinition);
    if (validationResult[0].message != 'ok') {
      throw new Error(`${SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID}`);
    }
  }

  static async validatePresentationsAgainstDefinitions(
    definitions: PresentationDefinitionWithLocation[],
    vpPayloads: WrappedVerifiablePresentation[],
    verifyPresentationCallback: PresentationVerificationCallback | undefined,
    opts?: {
      limitDisclosureSignatureSuites?: string[];
      restrictToFormats?: Format;
      restrictToDIDMethods?: string[];
      presentationSubmission?: PresentationSubmission;
      hasher?: Hasher;
    },
  ) {
    if (!definitions || !vpPayloads || !definitions.length || definitions.length !== vpPayloads.length) {
      throw new Error(SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD);
    }
    await Promise.all(
      definitions.map(
        async (pd) => await PresentationExchange.validatePresentationsAgainstDefinition(pd.definition, vpPayloads, verifyPresentationCallback, opts),
      ),
    );
  }

  private static async validatePresentationsAgainstDefinition(
    definition: IPresentationDefinition,
    vpPayloads: WrappedVerifiablePresentation[],
    verifyPresentationCallback: PresentationVerificationCallback | undefined,
    opts?: {
      limitDisclosureSignatureSuites?: string[];
      restrictToFormats?: Format;
      restrictToDIDMethods?: string[];
      presentationSubmission?: PresentationSubmission;
      hasher?: Hasher;
    },
  ) {
    const pex = new PEX({ hasher: opts?.hasher });

    function filterOutCorrectPresentation() {
      //TODO: add support for multiple VPs here
      return vpPayloads.filter(async (vpw: WrappedVerifiablePresentation) => {
        const presentationSubmission =
          opts?.presentationSubmission ??
          (CredentialMapper.isWrappedW3CVerifiablePresentation(vpw) ? vpw.presentation.presentation_submission : undefined);
        const presentation = vpw.presentation;
        if (!definition) {
          throw new Error(SIOPErrors.NO_PRESENTATION_SUBMISSION);
        } else if (
          !vpw.presentation ||
          (CredentialMapper.isWrappedW3CVerifiablePresentation(vpw) &&
            (!vpw.presentation.verifiableCredential || vpw.presentation.verifiableCredential.length === 0))
        ) {
          throw new Error(SIOPErrors.NO_VERIFIABLE_PRESENTATION_NO_CREDENTIALS);
        }
        // The verifyPresentationCallback function is mandatory for RP only,
        // So the behavior here is to bypass it if not present
        if (verifyPresentationCallback) {
          try {
            await verifyPresentationCallback(vpw.original as W3CVerifiablePresentation, presentationSubmission);
          } catch (error: unknown) {
            throw new Error(SIOPErrors.VERIFIABLE_PRESENTATION_SIGNATURE_NOT_VALID);
          }
        }
        // console.log(`Presentation (filter): ${JSON.stringify(presentation)}`);

        const evaluationResults = pex.evaluatePresentation(definition, vpw.original, {
          ...opts,
          presentationSubmission,
        });
        const submission = evaluationResults.value;
        if (!presentation || !submission) {
          throw new Error(SIOPErrors.NO_PRESENTATION_SUBMISSION);
        }
        return submission && submission.definition_id === definition.id;
      });
    }

    const checkedPresentations: WrappedVerifiablePresentation[] = filterOutCorrectPresentation();

    if (checkedPresentations.length !== 1) {
      throw new Error(`${SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}`);
    }
    const checkedPresentation = checkedPresentations[0];
    const presentation = checkedPresentation.presentation;
    // console.log(`Presentation (checked): ${JSON.stringify(checkedPresentation.presentation)}`);
    if (
      !checkedPresentation.presentation ||
      (CredentialMapper.isWrappedW3CVerifiablePresentation(checkedPresentation) &&
        (!checkedPresentation.presentation.verifiableCredential || checkedPresentation.presentation.verifiableCredential.length === 0))
    ) {
      throw new Error(SIOPErrors.NO_VERIFIABLE_PRESENTATION_NO_CREDENTIALS);
    }
    const presentationSubmission =
      opts?.presentationSubmission ?? (CredentialMapper.isW3cPresentation(presentation) ? presentation.presentation_submission : undefined);
    const evaluationResults = pex.evaluatePresentation(definition, checkedPresentation.original, {
      ...opts,
      presentationSubmission,
    });
    PresentationExchange.assertValidPresentationSubmission(evaluationResults.value);
    await PresentationExchange.validatePresentationAgainstDefinition(definition, checkedPresentation, {
      ...opts,
      presentationSubmission,
      hasher: opts?.hasher,
    });
  }
}
