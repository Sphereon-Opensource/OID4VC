import { CredentialFormat } from '@sphereon/ssi-types';
import Debug from 'debug';

import { CredentialRequestClientBuilder } from './CredentialRequestClientBuilder';
import { ProofOfPossessionBuilder } from './ProofOfPossessionBuilder';
import { isValidURL, post } from './functions';
import { CredentialRequest, CredentialResponse, OpenIDResponse, ProofOfPossession, ProofOfPossessionArgs, URL_NOT_VALID } from './types';

const debug = Debug('sphereon:openid4vci:credential');

export class CredentialRequestClient {
  _issuanceRequestOpts: Partial<{
    credentialEndpoint: string;
    clientId: string;
    credentialType: string | string[];
    format: CredentialFormat | CredentialFormat[];
    proof: ProofOfPossession;
    token: string;
  }>;

  public getCredentialEndpoint(): string {
    return this._issuanceRequestOpts.credentialEndpoint;
  }

  public getClientId(): string {
    return this._issuanceRequestOpts.clientId;
  }

  public constructor(builder: CredentialRequestClientBuilder) {
    this._issuanceRequestOpts = { ...builder };
  }

  public static builder(): CredentialRequestClientBuilder {
    return new CredentialRequestClientBuilder();
  }

  public async acquireCredentialsUsingProof(
    proof: ProofOfPossession | ProofOfPossessionArgs,
    opts?: {
      credentialType?: string | string[];
      format?: CredentialFormat | CredentialFormat[];
      overrideIssuerURL?: string;
      overrideAccessToken?: string;
    }
  ): Promise<OpenIDResponse<CredentialResponse>> {
    const proofOfPossession = proof.proofOfPossessionCallback
      ? await ProofOfPossessionBuilder.fromProofCallbackArgs(proof as ProofOfPossessionArgs).build()
      : await ProofOfPossessionBuilder.fromProof(proof as ProofOfPossession).build();
    const request = await this.createCredentialRequest(proofOfPossession, { ...opts });
    return await this.acquireCredentialsUsingRequest(request, { ...opts });
  }

  public async acquireCredentialsUsingRequest(
    request: CredentialRequest,
    opts?: { overrideCredentialEndpoint?: string; overrideAccessToken?: string }
  ): Promise<OpenIDResponse<CredentialResponse>> {
    const credentialEndpoint: string = opts?.overrideCredentialEndpoint
      ? opts.overrideCredentialEndpoint
      : this._issuanceRequestOpts.credentialEndpoint;
    if (!isValidURL(credentialEndpoint)) {
      debug(`Invalid credential endpoint: ${credentialEndpoint}`);
      throw new Error(URL_NOT_VALID);
    }
    debug(`Acquiring credential(s) from: ${credentialEndpoint}`);
    const requestToken: string = opts?.overrideAccessToken ? opts.overrideAccessToken : this._issuanceRequestOpts.token;
    const response: OpenIDResponse<CredentialResponse> = await post(credentialEndpoint, JSON.stringify(request), { bearerToken: requestToken });
    debug(`Credential endpoint ${credentialEndpoint} response:\r\n${response}`);
    return response;
  }

  public async createCredentialRequest(
    proof: ProofOfPossession | ProofOfPossessionArgs,
    opts?: {
      credentialType?: string | string[];
      format?: CredentialFormat | CredentialFormat[];
    }
  ): Promise<CredentialRequest> {
    const proofOfPossession = proof.proofOfPossessionCallback
      ? await ProofOfPossessionBuilder.fromProofCallbackArgs(proof as ProofOfPossessionArgs).build()
      : await ProofOfPossessionBuilder.fromProof(proof as ProofOfPossession).build();
    return {
      type: opts?.credentialType ? opts.credentialType : this._issuanceRequestOpts.credentialType,
      format: opts?.format ? opts.format : this._issuanceRequestOpts.format,
      proof: proofOfPossession,
    };
  }
}
