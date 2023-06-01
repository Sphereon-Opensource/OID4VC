import {
  CredentialRequestV1_0_08,
  CredentialResponse,
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

const debug = Debug('sphereon:openid4vci:credential');

export interface CredentialRequestOpts {
  credentialEndpoint: string;
  credentialTypes: string[];
  format?: CredentialFormat | OID4VCICredentialFormat;
  proof: ProofOfPossession;
  token: string;
  version?: OpenId4VCIVersion;
}

export class CredentialRequestClient {
  private readonly _credentialRequestOpts: Partial<CredentialRequestOpts>;

  get credentialRequestOpts(): CredentialRequestOpts {
    return this._credentialRequestOpts as CredentialRequestOpts;
  }

  public getCredentialEndpoint(): string {
    return this.credentialRequestOpts.credentialEndpoint;
  }

  public constructor(builder: CredentialRequestClientBuilder) {
    this._credentialRequestOpts = { ...builder };
  }

  public async acquireCredentialsUsingProof(opts: {
    proofInput: ProofOfPossessionBuilder | ProofOfPossession;
    credentialTypes?: string | string[];
    format?: CredentialFormat | OID4VCICredentialFormat;
  }): Promise<OpenIDResponse<CredentialResponse>> {
    const { credentialTypes, proofInput, format } = opts;

    const request = await this.createCredentialRequest({ proofInput, credentialTypes, format });
    return await this.acquireCredentialsUsingRequest(request);
  }

  public async acquireCredentialsUsingRequest(uniformRequest: UniformCredentialRequest): Promise<OpenIDResponse<CredentialResponse>> {
    let request: CredentialRequestV1_0_08 | UniformCredentialRequest = uniformRequest;
    if (!this.isV11OrHigher()) {
      request = {
        format: uniformRequest.format,
        proof: uniformRequest.proof,
        type: 'types' in uniformRequest ? uniformRequest.types[0] : uniformRequest.credential_definition.types[0],
      } as CredentialRequestV1_0_08;
    }
    const credentialEndpoint: string = this.credentialRequestOpts.credentialEndpoint;
    if (!isValidURL(credentialEndpoint)) {
      debug(`Invalid credential endpoint: ${credentialEndpoint}`);
      throw new Error(URL_NOT_VALID);
    }
    debug(`Acquiring credential(s) from: ${credentialEndpoint}`);
    const requestToken: string = this.credentialRequestOpts.token;
    const response: OpenIDResponse<CredentialResponse> = await post(credentialEndpoint, JSON.stringify(request), { bearerToken: requestToken });
    debug(`Credential endpoint ${credentialEndpoint} response:\r\n${response}`);
    return response;
  }

  public async createCredentialRequest(opts: {
    proofInput: ProofOfPossessionBuilder | ProofOfPossession;
    credentialTypes?: string | string[];
    format?: CredentialFormat | OID4VCICredentialFormat;
  }): Promise<UniformCredentialRequest> {
    const { proofInput } = opts;
    const formatSelection = opts.format ?? this.credentialRequestOpts.format;
    const format: OID4VCICredentialFormat = (
      formatSelection === 'jwt_vc' || formatSelection === 'jwt' ? 'jwt_vc_json-ld' : formatSelection
    ) as OID4VCICredentialFormat;
    if (!format) {
      throw Error(`Format of credential to be issued is missing`);
    } else if (format !== 'jwt_vc_json-ld' && format !== 'jwt_vc_json' && format !== 'ldp_vc') {
      throw Error(`Invalid format of credential to be issued: ${format}`);
    }
    const typesSelection =
      opts?.credentialTypes && (typeof opts.credentialTypes === 'string' || opts.credentialTypes.length > 0)
        ? opts.credentialTypes
        : this.credentialRequestOpts.credentialTypes;
    const types = Array.isArray(typesSelection) ? typesSelection : [typesSelection];
    if (types.length === 0) {
      throw Error(`Credential type(s) need to be provided`);
    } else if (!this.isV11OrHigher() && types.length !== 1) {
      throw Error('Only a single credential type is supported for V8/V9');
    }

    const proof =
      'proof_type' in proofInput ? await ProofOfPossessionBuilder.fromProof(proofInput as ProofOfPossession).build() : await proofInput.build();
    return {
      types,
      format,
      proof,
    } as UniformCredentialRequest;
  }

  private isV11OrHigher(): boolean {
    return !this.credentialRequestOpts.version || this.credentialRequestOpts.version >= OpenId4VCIVersion.VER_1_0_11;
  }
}
