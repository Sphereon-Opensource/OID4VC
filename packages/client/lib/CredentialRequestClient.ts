import {
  acquireDeferredCredential,
  CredentialResponse,
  getCredentialRequestForVersion,
  getUniformFormat,
  isDeferredCredentialResponse,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
  OpenIDResponse,
  ProofOfPossession,
  UniformCredentialRequest,
  URL_NOT_VALID,
} from '@sphereon/oid4vci-common';
import { CredentialFormat } from '@sphereon/ssi-types';
import Debug from 'debug';

import { CredentialRequestClientBuilder } from './CredentialRequestClientBuilder';
import { ProofOfPossessionBuilder } from './ProofOfPossessionBuilder';
import { isValidURL, post } from './functions';

const debug = Debug('sphereon:oid4vci:credential');

export interface CredentialRequestOpts {
  deferredCredentialAwait?: boolean;
  deferredCredentialIntervalInMS?: number;
  credentialEndpoint: string;
  deferredCredentialEndpoint?: string;
  credentialTypes: string[];
  format?: CredentialFormat | OID4VCICredentialFormat;
  proof: ProofOfPossession;
  token: string;
  version: OpenId4VCIVersion;
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
      throw Error(`Cnonce param is only supported when using a Proof of Posession builder`);
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
    credentialTypes?: string | string[];
    context?: string[];
    format?: CredentialFormat | OID4VCICredentialFormat;
  }): Promise<OpenIDResponse<CredentialResponse>> {
    const { credentialTypes, proofInput, format, context } = opts;

    const request = await this.createCredentialRequest({ proofInput, credentialTypes, context, format, version: this.version() });
    return await this.acquireCredentialsUsingRequest(request);
  }

  public async acquireCredentialsUsingRequest(uniformRequest: UniformCredentialRequest): Promise<OpenIDResponse<CredentialResponse>> {
    const request = getCredentialRequestForVersion(uniformRequest, this.version());
    const credentialEndpoint: string = this.credentialRequestOpts.credentialEndpoint;
    if (!isValidURL(credentialEndpoint)) {
      debug(`Invalid credential endpoint: ${credentialEndpoint}`);
      throw new Error(URL_NOT_VALID);
    }
    debug(`Acquiring credential(s) from: ${credentialEndpoint}`);
    debug(`request\n: ${JSON.stringify(request, null, 2)}`);
    const requestToken: string = this.credentialRequestOpts.token;
    let response: OpenIDResponse<CredentialResponse> = await post(credentialEndpoint, JSON.stringify(request), { bearerToken: requestToken });
    this._isDeferred = isDeferredCredentialResponse(response);
    if (this.isDeferred() && this.credentialRequestOpts.deferredCredentialAwait && response.successBody) {
      response = await this.acquireDeferredCredential(response.successBody, { bearerToken: this.credentialRequestOpts.token });
    }

    debug(`Credential endpoint ${credentialEndpoint} response:\r\n${JSON.stringify(response, null, 2)}`);
    return response;
  }

  public async acquireDeferredCredential(
    response: Pick<CredentialResponse, 'transaction_id' | 'acceptance_token' | 'c_nonce'>,
    opts?: {
      bearerToken?: string;
    },
  ): Promise<OpenIDResponse<CredentialResponse>> {
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
    credentialTypes?: string | string[];
    context?: string[];
    format?: CredentialFormat | OID4VCICredentialFormat;
    version: OpenId4VCIVersion;
  }): Promise<UniformCredentialRequest> {
    const { proofInput } = opts;
    const formatSelection = opts.format ?? this.credentialRequestOpts.format;

    if (!formatSelection) {
      throw Error(`Format of credential to be issued is missing`);
    }
    const format = getUniformFormat(formatSelection);
    const typesSelection =
      opts?.credentialTypes && (typeof opts.credentialTypes === 'string' || opts.credentialTypes.length > 0)
        ? opts.credentialTypes
        : this.credentialRequestOpts.credentialTypes;
    const types = Array.isArray(typesSelection) ? typesSelection : [typesSelection];
    if (types.length === 0) {
      throw Error(`Credential type(s) need to be provided`);
    }
    // FIXME: this is mixing up the type (as id) from v8/v9 and the types (from the vc.type) from v11
    else if (!this.isV11OrHigher() && types.length !== 1) {
      throw Error('Only a single credential type is supported for V8/V9');
    }
    const proof = await buildProof(proofInput, opts);

    // TODO: we should move format specific logic
    if (format === 'jwt_vc_json' || format === 'jwt_vc') {
      return {
        types,
        format,
        proof,
      };
    } else if (format === 'jwt_vc_json-ld' || format === 'ldp_vc') {
      if (this.version() >= OpenId4VCIVersion.VER_1_0_12 && !opts.context) {
        throw Error('No @context value present, but it is required');
      }

      return {
        format,
        proof,

        // Ignored because v11 does not have the context value, but it is required in v12
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        credential_definition: {
          types,
          ...(opts.context && { '@context': opts.context }),
        },
      };
    } else if (format === 'vc+sd-jwt') {
      if (types.length > 1) {
        throw Error(`Only a single credential type is supported for ${format}`);
      }

      return {
        format,
        proof,
        vct: types[0],
      };
    }

    throw new Error(`Unsupported format: ${format}`);
  }

  private version(): OpenId4VCIVersion {
    return this.credentialRequestOpts?.version ?? OpenId4VCIVersion.VER_1_0_11;
  }

  private isV11OrHigher(): boolean {
    return this.version() >= OpenId4VCIVersion.VER_1_0_11;
  }
}
