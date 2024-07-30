import { createDPoP, CreateDPoPClientOpts, getCreateDPoPOptions } from '@sphereon/oid4vc-common';
import {
  acquireDeferredCredential,
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
import { CredentialFormat } from '@sphereon/ssi-types';
import Debug from 'debug';

import { buildProof } from './CredentialRequestClient';
import { CredentialRequestClientBuilderV1_0_11 } from './CredentialRequestClientBuilderV1_0_11';
import { ProofOfPossessionBuilder } from './ProofOfPossessionBuilder';

const debug = Debug('sphereon:oid4vci:credential');

export interface CredentialRequestOptsV1_0_11 {
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

export class CredentialRequestClientV1_0_11 {
  private readonly _credentialRequestOpts: Partial<CredentialRequestOptsV1_0_11>;
  private _isDeferred = false;

  get credentialRequestOpts(): CredentialRequestOptsV1_0_11 {
    return this._credentialRequestOpts as CredentialRequestOptsV1_0_11;
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

  public constructor(builder: CredentialRequestClientBuilderV1_0_11) {
    this._credentialRequestOpts = { ...builder };
  }

  public async acquireCredentialsUsingProof<DIDDoc>(opts: {
    proofInput: ProofOfPossessionBuilder<DIDDoc> | ProofOfPossession;
    credentialTypes?: string | string[];
    context?: string[];
    format?: CredentialFormat | OID4VCICredentialFormat;
    createDPoPOpts?: CreateDPoPClientOpts;
  }): Promise<OpenIDResponse<CredentialResponse> & { access_token: string }> {
    const { credentialTypes, proofInput, format, context } = opts;

    const request = await this.createCredentialRequest({ proofInput, credentialTypes, context, format, version: this.version() });
    return await this.acquireCredentialsUsingRequest(request, opts.createDPoPOpts);
  }

  public async acquireCredentialsUsingRequest(
    uniformRequest: UniformCredentialRequest,
    createDPoPOpts?: CreateDPoPClientOpts,
  ): Promise<OpenIDResponse<CredentialResponse> & { access_token: string }> {
    const request = getCredentialRequestForVersion(uniformRequest, this.version());
    const credentialEndpoint: string = this.credentialRequestOpts.credentialEndpoint;
    if (!isValidURL(credentialEndpoint)) {
      debug(`Invalid credential endpoint: ${credentialEndpoint}`);
      throw new Error(URL_NOT_VALID);
    }
    debug(`Acquiring credential(s) from: ${credentialEndpoint}`);
    debug(`request\n: ${JSON.stringify(request, null, 2)}`);
    const requestToken: string = this.credentialRequestOpts.token;

    let dPoP: string | undefined;
    if (createDPoPOpts) {
      dPoP = createDPoPOpts ? await createDPoP(getCreateDPoPOptions(createDPoPOpts, credentialEndpoint, { accessToken: requestToken })) : undefined;
    }

    let response = (await post(credentialEndpoint, JSON.stringify(request), {
      bearerToken: requestToken,
      customHeaders: { ...(createDPoPOpts && { dpop: dPoP }) },
    })) as OpenIDResponse<CredentialResponse> & {
      access_token: string;
    };
    this._isDeferred = isDeferredCredentialResponse(response);
    if (this.isDeferred() && this.credentialRequestOpts.deferredCredentialAwait && response.successBody) {
      response = await this.acquireDeferredCredential(response.successBody, { bearerToken: this.credentialRequestOpts.token });
    }
    response.access_token = requestToken;

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
        } as JsonLdIssuerCredentialDefinition,
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
