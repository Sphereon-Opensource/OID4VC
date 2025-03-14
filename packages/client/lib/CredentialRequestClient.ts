import { createDPoP, CreateDPoPClientOpts, getCreateDPoPOptions } from '@sphereon/oid4vc-common';
import {
  acquireDeferredCredential,
  CredentialRequestV1_0_13,
  CredentialRequestWithoutProofV1_0_13,
  CredentialResponse,
  DPoPResponseParams,
  ExperimentalSubjectIssuance,
  getCredentialRequestForVersion,
  getUniformFormat,
  isDeferredCredentialResponse,
  isValidURL,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
  OpenIDResponse,
  post,
  ProofOfPossession,
  UniformCredentialRequest,
  URL_NOT_VALID,
} from '@sphereon/oid4vci-common';
import { CredentialFormat } from '@sphereon/ssi-types';
import Debug from 'debug';

import { CredentialRequestClientBuilderV1_0_11 } from './CredentialRequestClientBuilderV1_0_11';
import { CredentialRequestClientBuilderV1_0_13 } from './CredentialRequestClientBuilderV1_0_13';
import { ProofOfPossessionBuilder } from './ProofOfPossessionBuilder';
import { shouldRetryResourceRequestWithDPoPNonce } from './functions/dpopUtil';

const debug = Debug('sphereon:oid4vci:credential');

export interface CredentialRequestOpts {
  deferredCredentialAwait?: boolean;
  deferredCredentialIntervalInMS?: number;
  credentialEndpoint: string;
  notificationEndpoint?: string;
  deferredCredentialEndpoint?: string;
  credentialTypes?: string[];
  credentialIdentifier?: string;
  format?: CredentialFormat | OID4VCICredentialFormat;
  proof: ProofOfPossession;
  token: string;
  version: OpenId4VCIVersion;
  subjectIssuance?: ExperimentalSubjectIssuance;
  issuerState?: string;
}

export type CreateCredentialRequestOpts = {
  credentialIdentifier?: string;
  credentialTypes?: string | string[];
  context?: string[];
  format?: CredentialFormat | OID4VCICredentialFormat;
  subjectIssuance?: ExperimentalSubjectIssuance;
  version: OpenId4VCIVersion;
};

export async function buildProof(
  proofInput: ProofOfPossessionBuilder | ProofOfPossession,
  opts: {
    version: OpenId4VCIVersion;
    cNonce?: string;
  },
) {
  if ('proof_type' in proofInput) {
    if (opts.cNonce) {
      throw Error(`Cnonce param is only supported when using a Proof of possession builder`);
    }
    return await ProofOfPossessionBuilder.fromProof(proofInput as ProofOfPossession, opts.version).build();
  }
  if (opts.cNonce) {
    proofInput.withAccessTokenNonce(opts.cNonce);
  }
  return await proofInput.build();
}

export class CredentialRequestClient {
  private readonly _credentialRequestOpts: Partial<CredentialRequestOpts>;
  private _isDeferred = false;

  get credentialRequestOpts(): CredentialRequestOpts {
    return this._credentialRequestOpts as CredentialRequestOpts;
  }

  public isDeferred(): boolean {
    return this._isDeferred;
  }

  public getCredentialEndpoint(): string {
    return this.credentialRequestOpts.credentialEndpoint;
  }

  public getDeferredCredentialEndpoint(): string | undefined {
    return this.credentialRequestOpts.deferredCredentialEndpoint;
  }

  public constructor(builder: CredentialRequestClientBuilderV1_0_13 | CredentialRequestClientBuilderV1_0_11) {
    this._credentialRequestOpts = { ...builder };
  }

  /**
   * Typically you should not use this method, as it omits a proof from the request.
   * There are certain issuers that in specific circumstances can do without this proof, because they have other means of user binding
   * like using DPoP together with an authorization code flow. These are however rare, so you should be using the acquireCredentialsUsingProof normally
   * @param opts
   */
  public async acquireCredentialsWithoutProof(opts: {
    credentialIdentifier?: string;
    credentialTypes?: string | string[];
    context?: string[];
    format?: CredentialFormat | OID4VCICredentialFormat;
    subjectIssuance?: ExperimentalSubjectIssuance;
    createDPoPOpts?: CreateDPoPClientOpts;
  }): Promise<OpenIDResponse<CredentialResponse, DPoPResponseParams> & { access_token: string }> {
    const { credentialIdentifier, credentialTypes, format, context, subjectIssuance } = opts;

    const request = await this.createCredentialRequestWithoutProof({
      credentialTypes,
      context,
      format,
      version: this.version(),
      credentialIdentifier,
      subjectIssuance,
    });
    return await this.acquireCredentialsUsingRequestWithoutProof(request, opts.createDPoPOpts);
  }

  public async acquireCredentialsUsingProof(opts: {
    proofInput: ProofOfPossessionBuilder | ProofOfPossession;
    credentialIdentifier?: string;
    credentialTypes?: string | string[];
    context?: string[];
    format?: CredentialFormat | OID4VCICredentialFormat;
    subjectIssuance?: ExperimentalSubjectIssuance;
    createDPoPOpts?: CreateDPoPClientOpts;
  }): Promise<OpenIDResponse<CredentialResponse, DPoPResponseParams> & { access_token: string }> {
    const { credentialIdentifier, credentialTypes, proofInput, format, context, subjectIssuance } = opts;

    const request = await this.createCredentialRequest({
      proofInput,
      credentialTypes,
      context,
      format,
      version: this.version(),
      credentialIdentifier,
      subjectIssuance,
    });
    return await this.acquireCredentialsUsingRequest(request, opts.createDPoPOpts);
  }

  public async acquireCredentialsUsingRequestWithoutProof(
    uniformRequest: UniformCredentialRequest,
    createDPoPOpts?: CreateDPoPClientOpts,
  ): Promise<OpenIDResponse<CredentialResponse, DPoPResponseParams> & { access_token: string }> {
    return await this.acquireCredentialsUsingRequestImpl(uniformRequest, createDPoPOpts);
  }

  public async acquireCredentialsUsingRequest(
    uniformRequest: UniformCredentialRequest,
    createDPoPOpts?: CreateDPoPClientOpts,
  ): Promise<OpenIDResponse<CredentialResponse, DPoPResponseParams> & { access_token: string }> {
    return await this.acquireCredentialsUsingRequestImpl(uniformRequest, createDPoPOpts);
  }

  private async acquireCredentialsUsingRequestImpl(
    uniformRequest: UniformCredentialRequest & { proof?: ProofOfPossession },
    createDPoPOpts?: CreateDPoPClientOpts,
  ): Promise<OpenIDResponse<CredentialResponse, DPoPResponseParams> & { access_token: string }> {
    if (this.version() < OpenId4VCIVersion.VER_1_0_13) {
      throw new Error('Versions below v1.0.13 (draft 13) are not supported by the V13 credential request client.');
    }
    const request: CredentialRequestV1_0_13 = getCredentialRequestForVersion(uniformRequest, this.version()) as CredentialRequestV1_0_13;
    const credentialEndpoint: string = this.credentialRequestOpts.credentialEndpoint;
    if (!isValidURL(credentialEndpoint)) {
      debug(`Invalid credential endpoint: ${credentialEndpoint}`);
      throw new Error(URL_NOT_VALID);
    }
    debug(`Acquiring credential(s) from: ${credentialEndpoint}`);
    debug(`request\n: ${JSON.stringify(request, null, 2)}`);
    const requestToken: string = this.credentialRequestOpts.token;

    let dPoP = createDPoPOpts ? await createDPoP(getCreateDPoPOptions(createDPoPOpts, credentialEndpoint, { accessToken: requestToken })) : undefined;

    let response = (await post(credentialEndpoint, JSON.stringify(request), {
      bearerToken: requestToken,
      ...(dPoP && { customHeaders: { dpop: dPoP } }),
    })) as OpenIDResponse<CredentialResponse> & {
      access_token: string;
    };

    let nextDPoPNonce = createDPoPOpts?.jwtPayloadProps.nonce;
    const retryWithNonce = shouldRetryResourceRequestWithDPoPNonce(response);
    if (retryWithNonce.ok && createDPoPOpts) {
      createDPoPOpts.jwtPayloadProps.nonce = retryWithNonce.dpopNonce;
      dPoP = await createDPoP(getCreateDPoPOptions(createDPoPOpts, credentialEndpoint, { accessToken: requestToken }));

      response = (await post(credentialEndpoint, JSON.stringify(request), {
        bearerToken: requestToken,
        ...(createDPoPOpts && { customHeaders: { dpop: dPoP } }),
      })) as OpenIDResponse<CredentialResponse> & {
        access_token: string;
      };

      const successDPoPNonce = response.origResponse.headers.get('DPoP-Nonce');
      nextDPoPNonce = successDPoPNonce ?? retryWithNonce.dpopNonce;
    }

    this._isDeferred = isDeferredCredentialResponse(response);
    if (this.isDeferred() && this.credentialRequestOpts.deferredCredentialAwait && response.successBody) {
      response = await this.acquireDeferredCredential(response.successBody, { bearerToken: this.credentialRequestOpts.token });
    }
    response.access_token = requestToken;

    if ((uniformRequest.credential_subject_issuance && response.successBody) || response.successBody?.credential_subject_issuance) {
      if (JSON.stringify(uniformRequest.credential_subject_issuance) !== JSON.stringify(response.successBody?.credential_subject_issuance)) {
        throw Error('Subject signing was requested, but issuer did not provide the options in its response');
      }
    }
    debug(`Credential endpoint ${credentialEndpoint} response:\r\n${JSON.stringify(response, null, 2)}`);

    return {
      ...response,
      ...(nextDPoPNonce && { params: { dpop: { dpopNonce: nextDPoPNonce } } }),
    };
  }

  public async acquireDeferredCredential(
    response: Pick<CredentialResponse, 'transaction_id' | 'acceptance_token' | 'c_nonce'>,
    opts?: {
      bearerToken?: string;
    },
  ): Promise<OpenIDResponse<CredentialResponse> & { access_token: string }> {
    const transactionId = response.transaction_id;
    const bearerToken = response.acceptance_token ?? opts?.bearerToken;
    const deferredCredentialEndpoint = this.getDeferredCredentialEndpoint();
    if (!deferredCredentialEndpoint) {
      throw Error(`No deferred credential endpoint supplied.`);
    } else if (!bearerToken) {
      throw Error(`No bearer token present and refresh for defered endpoint not supported yet`);
      // todo updated bearer token with new c_nonce
    }
    return await acquireDeferredCredential({
      bearerToken,
      transactionId,
      deferredCredentialEndpoint,
      deferredCredentialAwait: this.credentialRequestOpts.deferredCredentialAwait,
      deferredCredentialIntervalInMS: this.credentialRequestOpts.deferredCredentialIntervalInMS,
    });
  }

  public async createCredentialRequestWithoutProof(opts: CreateCredentialRequestOpts): Promise<CredentialRequestWithoutProofV1_0_13> {
    return await this.createCredentialRequestImpl(opts);
  }

  public async createCredentialRequest(
    opts: CreateCredentialRequestOpts & {
      proofInput: ProofOfPossessionBuilder | ProofOfPossession;
    },
  ): Promise<CredentialRequestV1_0_13> {
    return await this.createCredentialRequestImpl(opts);
  }

  private async createCredentialRequestImpl(
    opts: CreateCredentialRequestOpts & {
      proofInput?: ProofOfPossessionBuilder | ProofOfPossession;
    },
  ): Promise<CredentialRequestV1_0_13> {
    const { proofInput, credentialIdentifier: credential_identifier } = opts;
    let proof: ProofOfPossession | undefined = undefined;
    if (proofInput) {
      proof = await buildProof(proofInput, opts);
    }
    if (credential_identifier) {
      if (opts.format || opts.credentialTypes || opts.context) {
        throw Error(`You cannot mix credential_identifier with format, credential types and/or context`);
      }
      return {
        credential_identifier,
        ...(proof && { proof }),
      };
    }
    const formatSelection = opts.format ?? this.credentialRequestOpts.format;

    if (!formatSelection) {
      throw Error(`Format of credential to be issued is missing`);
    }
    const format = getUniformFormat(formatSelection);
    const typesSelection =
      opts?.credentialTypes && (typeof opts.credentialTypes === 'string' || opts.credentialTypes.length > 0)
        ? opts.credentialTypes
        : this.credentialRequestOpts.credentialTypes;
    if (!typesSelection) {
      throw Error(`Credential type(s) need to be provided`);
    }
    const types = Array.isArray(typesSelection) ? typesSelection : [typesSelection];
    if (types.length === 0) {
      throw Error(`Credential type(s) need to be provided`);
    }
    const issuer_state = this.credentialRequestOpts.issuerState;

    // TODO: we should move format specific logic
    if (format === 'jwt_vc_json' || format === 'jwt_vc') {
      return {
        credential_definition: {
          type: types,
        },
        format,
        ...(issuer_state && { issuer_state }),
        ...(proof && { proof }),
        ...opts.subjectIssuance,
      };
    } else if (format === 'jwt_vc_json-ld' || format === 'ldp_vc') {
      if (this.version() >= OpenId4VCIVersion.VER_1_0_12 && !opts.context) {
        throw Error('No @context value present, but it is required');
      }

      return {
        format,
        ...(issuer_state && { issuer_state }),
        ...(proof && { proof }),
        ...opts.subjectIssuance,

        credential_definition: {
          type: types,
          '@context': opts.context as string[],
        },
      };
    } else if (format === 'vc+sd-jwt') {
      if (types.length > 1) {
        throw Error(`Only a single credential type is supported for ${format}`);
      }
      return {
        format,
        ...(issuer_state && { issuer_state }),
        ...(proof && { proof }),
        vct: types[0],
        ...opts.subjectIssuance,
      };
    } else if (format === 'mso_mdoc') {
      if (types.length > 1) {
        throw Error(`Only a single credential type is supported for ${format}`);
      }
      return {
        format,
        ...(issuer_state && { issuer_state }),
        ...(proof && { proof }),
        doctype: types[0],
        ...opts.subjectIssuance,
      };
    }

    throw new Error(`Unsupported credential format: ${format}`);
  }

  private version(): OpenId4VCIVersion {
    return this.credentialRequestOpts?.version ?? OpenId4VCIVersion.VER_1_0_13;
  }
}
