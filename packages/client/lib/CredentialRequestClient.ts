import { CredentialRequest, CredentialResponse, OpenIDResponse, ProofOfPossession, URL_NOT_VALID } from '@sphereon/openid4vci-common';
import { CredentialFormat } from '@sphereon/ssi-types';
import Debug from 'debug';

import { ProofOfPossessionBuilder } from './ProofOfPossessionBuilder';
import { isValidURL, post } from './functions';
import {CredentialRequestClientBuilder} from "./CredentialRequestClientBuilder";


const debug = Debug('sphereon:openid4vci:credential');

export interface CredentialRequestOpts {
  credentialEndpoint: string;
  credentialType: string | string[];
  format: CredentialFormat | CredentialFormat[];
  proof: ProofOfPossession;
  token: string;
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

  public async acquireCredentialsUsingProof({
    proofInput,
    credentialType,
    format,
  }: {
    proofInput: ProofOfPossessionBuilder | ProofOfPossession;
    credentialType?: string | string[];
    format?: CredentialFormat | CredentialFormat[];
  }): Promise<OpenIDResponse<CredentialResponse>> {
    const request = await this.createCredentialRequest({ proofInput, credentialType, format });
    return await this.acquireCredentialsUsingRequest(request);
  }

  public async acquireCredentialsUsingRequest(request: CredentialRequest): Promise<OpenIDResponse<CredentialResponse>> {
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

  public async createCredentialRequest({
    proofInput,
    credentialType,
    format,
  }: {
    proofInput: ProofOfPossessionBuilder | ProofOfPossession;
    credentialType?: string | string[];
    format?: CredentialFormat | CredentialFormat[];
  }): Promise<CredentialRequest> {
    const proof =
      'proof_type' in proofInput ? await ProofOfPossessionBuilder.fromProof(proofInput as ProofOfPossession).build() : await proofInput.build();
    return {
      type: credentialType ? credentialType : this.credentialRequestOpts.credentialType,
      format: format ? format : this.credentialRequestOpts.format,
      proof,
    };
  }
}
