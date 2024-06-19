import {
  acquireDeferredCredential,
  CredentialRequestV1_0_13,
  CredentialResponse,
  getCredentialRequestForVersion,
  getUniformFormat,
  isDeferredCredentialResponse,
  isValidURL,
  JsonLdIssuerCredentialDefinition,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
  OpenIDResponse,
  post,
  ProofOfPossession,
  UniformCredentialRequest,
  URL_NOT_VALID,
} from '@sphereon/oid4vci-common';
import { ExperimentalSubjectIssuance } from '@sphereon/oid4vci-common/dist/experimental/holder-vci';
import { CredentialFormat } from '@sphereon/ssi-types';
import Debug from 'debug';

import { CredentialRequestClientBuilder } from './CredentialRequestClientBuilder';
import { ProofOfPossessionBuilder } from './ProofOfPossessionBuilder';

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
}

export async function buildProof<DIDDoc>(
  proofInput: ProofOfPossessionBuilder<DIDDoc> | ProofOfPossession,
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

  public constructor(builder: CredentialRequestClientBuilder) {
    this._credentialRequestOpts = { ...builder };
  }

  public async acquireCredentialsUsingProof<DIDDoc>(opts: {
    proofInput: ProofOfPossessionBuilder<DIDDoc> | ProofOfPossession;
    credentialIdentifier?: string;
    credentialTypes?: string | string[];
    context?: string[];
    format?: CredentialFormat | OID4VCICredentialFormat;
    subjectIssuance?: ExperimentalSubjectIssuance;
  }): Promise<OpenIDResponse<CredentialResponse> & { access_token: string }> {
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
    return await this.acquireCredentialsUsingRequest(request);
  }

  public async acquireCredentialsUsingRequest(
    uniformRequest: UniformCredentialRequest,
  ): Promise<OpenIDResponse<CredentialResponse> & { access_token: string }> {
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
    let response = (await post(credentialEndpoint, JSON.stringify(request), { bearerToken: requestToken })) as OpenIDResponse<CredentialResponse> & {
      access_token: string;
    };
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
    return response;
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

  public async createCredentialRequest<DIDDoc>(opts: {
    proofInput: ProofOfPossessionBuilder<DIDDoc> | ProofOfPossession;
    credentialIdentifier?: string;
    credentialTypes?: string | string[];
    context?: string[];
    format?: CredentialFormat | OID4VCICredentialFormat;
    subjectIssuance?: ExperimentalSubjectIssuance;
    version: OpenId4VCIVersion;
  }): Promise<CredentialRequestV1_0_13> {
    const { proofInput, credentialIdentifier: credential_identifier } = opts;
    const proof = await buildProof(proofInput, opts);
    if (credential_identifier) {
      if (opts.format || opts.credentialTypes || opts.context) {
        throw Error(`You cannot mix credential_identifier with format, credential types and/or context`);
      }
      return {
        credential_identifier,
        proof,
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

    // TODO: we should move format specific logic
    if (format === 'jwt_vc_json' || format === 'jwt_vc') {
      return {
        types,
        format,
        proof,
        ...opts.subjectIssuance,
      };
    } else if (format === 'jwt_vc_json-ld' || format === 'ldp_vc') {
      if (this.version() >= OpenId4VCIVersion.VER_1_0_12 && !opts.context) {
        throw Error('No @context value present, but it is required');
      }

      return {
        format,
        proof,
        ...opts.subjectIssuance,

        // Ignored because v11 does not have the context value, but it is required in v12
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        credential_definition: {
          types,
          ...(opts.context && { '@context': opts.context }),
        } as JsonLdIssuerCredentialDefinition,
      };
    } else if (format === 'vc+sd-jwt') {
      if (types.length > 1) {
        throw Error(`Only a single credential type is supported for ${format}`);
      }
      // fixme: this isn't up to the CredentialRequest that we see in the version v1_0_13
      return {
        format,
        proof,
        vct: types[0],
        ...opts.subjectIssuance,
      } as CredentialRequestV1_0_13;
    }

    throw new Error(`Unsupported format: ${format}`);
  }

  private version(): OpenId4VCIVersion {
    return this.credentialRequestOpts?.version ?? OpenId4VCIVersion.VER_1_0_13;
  }
}
