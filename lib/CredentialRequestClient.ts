import { CredentialFormat } from '@sphereon/ssi-types';

import { CredentialRequestClientBuilder } from './CredentialRequestClientBuilder';
import { ProofOfPossessionBuilder } from './ProofOfPossessionBuilder';
import { isValidURL, post } from './functions';
import { CredentialRequest, CredentialResponse, ErrorResponse, ProofOfPossession, ProofOfPossessionOpts, URL_NOT_VALID } from './types';

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
    proof: ProofOfPossession | ProofOfPossessionOpts,
    opts?: {
      credentialType?: string | string[];
      format?: CredentialFormat | CredentialFormat[];
      overrideIssuerURL?: string;
      overrideAccessToken?: string;
    }
  ): Promise<CredentialResponse | ErrorResponse> {
    const proofOfPossession =
      proof.proofOfPossessionCallback && proof.proofOfPossessionCallbackArgs
        ? await new ProofOfPossessionBuilder()
            .withProofOfPossessionCallback(
              (proof as ProofOfPossessionOpts).proofOfPossessionCallback,
              (proof as ProofOfPossessionOpts).proofOfPossessionCallbackArgs
            )
            .build()
        : await new ProofOfPossessionBuilder().withProofOfPossession(proof as ProofOfPossession).build();
    const request = await this.createCredentialRequest(proofOfPossession, { ...opts });
    return await this.acquireCredentialsUsingRequest(request, { ...opts });
  }

  public async acquireCredentialsUsingRequest(
    request: CredentialRequest,
    opts?: { overrideCredentialEndpoint?: string; overrideAccessToken?: string }
  ): Promise<CredentialResponse | ErrorResponse> {
    const credentialEndpoint: string = opts?.overrideCredentialEndpoint
      ? opts.overrideCredentialEndpoint
      : this._issuanceRequestOpts.credentialEndpoint;
    if (!isValidURL(credentialEndpoint)) {
      throw new Error(URL_NOT_VALID);
    }
    const requestToken: string = opts?.overrideAccessToken ? opts.overrideAccessToken : this._issuanceRequestOpts.token;
    const response = await post(credentialEndpoint, JSON.stringify(request), { bearerToken: requestToken });
    const responseJson = await response.json();
    if (responseJson.error) {
      return { ...responseJson } as ErrorResponse;
    }
    return { ...responseJson } as CredentialResponse;
  }

  public async createCredentialRequest(
    proof: ProofOfPossession | ProofOfPossessionOpts,
    opts?: {
      credentialType?: string | string[];
      format?: CredentialFormat | CredentialFormat[];
    }
  ): Promise<CredentialRequest> {
    const proofOfPossession =
      proof.proofOfPossessionCallback && proof.proofOfPossessionCallbackArgs
        ? await new ProofOfPossessionBuilder()
            .withProofOfPossessionCallback(
              (proof as ProofOfPossessionOpts).proofOfPossessionCallback,
              (proof as ProofOfPossessionOpts).proofOfPossessionCallbackArgs
            )
            .build()
        : await new ProofOfPossessionBuilder().withProofOfPossession(proof as ProofOfPossession).build();
    return {
      type: opts?.credentialType ? opts.credentialType : this._issuanceRequestOpts.credentialType,
      format: opts?.format ? opts.format : this._issuanceRequestOpts.format,
      proof: proofOfPossession,
    };
  }
}
