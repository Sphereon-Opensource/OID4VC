import { CredentialFormat } from '@sphereon/ssi-types';
import Debug from 'debug';

import { AccessTokenClient } from './AccessTokenClient';
import { CredentialRequestClientBuilder } from './CredentialRequestClientBuilder';
import { IssuanceInitiation } from './IssuanceInitiation';
import { MetadataClient } from './MetadataClient';
import { ProofOfPossessionBuilder } from './ProofOfPossessionBuilder';
import {
  AccessTokenResponse,
  Alg,
  AuthzFlowType,
  CredentialResponse,
  EndpointMetadata,
  IssuanceInitiationWithBaseUrl,
  ProofOfPossessionCallbacks,
} from './types';

const debug = Debug('sphereon:openid4vci:flow');

export class OpenID4VCIClient {
  private readonly _flowType: AuthzFlowType;
  private readonly _initiation: IssuanceInitiationWithBaseUrl;
  private readonly _clientId?: string;
  private readonly _kid: string;
  private readonly _alg: string;
  private _serverMetadata: EndpointMetadata;
  private _accessToken: AccessTokenResponse;

  private constructor(initiation: IssuanceInitiationWithBaseUrl, flowType: AuthzFlowType, kid: string, alg: Alg | string, clientId?: string) {
    if (flowType !== AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW) {
      throw new Error(`Only pre-authorized code flow is support at present`);
    }
    this._flowType = flowType;
    this._initiation = initiation;
    this._kid = kid;
    this._alg = alg;
    this._clientId = clientId;
  }

  public static async initiateFromURI({
    issuanceInitiationURI,
    flowType,
    kid,
    alg,
    retrieveServerMetadata,
    clientId,
  }: {
    issuanceInitiationURI: string;
    flowType: AuthzFlowType;
    kid: string;
    alg: Alg | string;
    retrieveServerMetadata?: boolean;
    clientId?: string;
  }): Promise<OpenID4VCIClient> {
    const flow = new OpenID4VCIClient(IssuanceInitiation.fromURI(issuanceInitiationURI), flowType, kid, alg, clientId);
    if (retrieveServerMetadata !== false) {
      await flow.retrieveServerMetadata();
    }
    return flow;
  }

  public async retrieveServerMetadata(): Promise<EndpointMetadata> {
    this.assertInitiation();
    if (!this._serverMetadata) {
      this._serverMetadata = await MetadataClient.retrieveAllMetadataFromInitiation(this._initiation);
    }
    return this._serverMetadata;
  }

  public async acquireAccessToken({ pin }: { pin?: string }): Promise<AccessTokenResponse> {
    this.assertInitiation();
    if (!this._accessToken) {
      const accessTokenClient = new AccessTokenClient();
      const response = await accessTokenClient.acquireAccessTokenUsingIssuanceInitiation({
        issuanceInitiation: this._initiation,
        metadata: this._serverMetadata,
        pin,
        asOpts: { clientId: this.clientId },
      });
      if (response.errorBody) {
        debug(`Access token error:\r\n${response.errorBody}`);
        throw Error(
          `Retrieving an access token from ${this._serverMetadata.token_endpoint} for issuer ${this._initiation.issuanceInitiationRequest.issuer} failed with status: ${response.origResponse.status}`
        );
      }
      this._accessToken = response.successBody;
    }
    return this._accessToken;
  }

  public async acquireCredentials({
    credentialType,
    proofCallbacks,
    format,
    jti,
  }: {
    credentialType: string | string[];
    proofCallbacks: ProofOfPossessionCallbacks;
    format?: CredentialFormat | CredentialFormat[];
    jti?: string;
  }): Promise<CredentialResponse> {
    const requestBuilder = CredentialRequestClientBuilder.fromIssuanceInitiation({
      initiation: this.initiation,
      metadata: this.serverMetadata,
    });
    if (this.serverMetadata?.openid4vci_metadata) {
      const metadata = this.serverMetadata.openid4vci_metadata;
      const types = Array.isArray(credentialType) ? credentialType : [credentialType];
      if (types.some((type) => !metadata.credentials_supported || !metadata.credentials_supported[type])) {
        throw Error(`Not all credential types ${JSON.stringify(credentialType)} are supported by issuer ${this.getIssuer()}`);
      }
      // todo: Format check? We might end up with some disjoint type / format combinations supported by the server
    }
    const credentialRequestClient = requestBuilder.build();
    const proofBuilder = ProofOfPossessionBuilder.fromAccessTokenResponse({
      accessTokenResponse: this.accessToken,
      callbacks: proofCallbacks,
    })
      .withIssuer(this.getIssuer())
      .withAlg(this.alg)
      .withJti(jti)
      .withClientId(this.clientId)
      .withKid(this.kid);

    const response = await credentialRequestClient.acquireCredentialsUsingProof({
      proofInput: proofBuilder,
      credentialType,
      format,
    });
    if (response.errorBody) {
      debug(`Access token error:\r\n${response.errorBody}`);
      throw Error(
        `Retrieving a credential from ${this._serverMetadata.credential_endpoint} for issuer ${this._initiation.issuanceInitiationRequest.issuer} failed with status: ${response.origResponse.status}`
      );
    }
    return response.successBody;
  }

  get flowType(): AuthzFlowType {
    return this._flowType;
  }

  get initiation(): IssuanceInitiationWithBaseUrl {
    return this._initiation;
  }

  get serverMetadata(): EndpointMetadata {
    return this._serverMetadata;
  }

  get kid(): string {
    return this._kid;
  }

  get alg(): string {
    return this._alg;
  }

  get clientId(): string {
    return this._clientId;
  }

  get accessToken(): AccessTokenResponse {
    return this._accessToken;
  }

  public getIssuer(): string {
    this.assertInitiation();
    return this._serverMetadata ? this.serverMetadata.issuer : this.initiation.issuanceInitiationRequest.issuer;
  }

  public getAccessTokenEndpoint(): string {
    this.assertInitiation();
    return this.serverMetadata
      ? this.serverMetadata.token_endpoint
      : AccessTokenClient.determineTokenURL({ issuerOpts: { issuer: this.getIssuer() } });
  }

  public getCredentialEndpoint(): string {
    this.assertInitiation();
    return this.serverMetadata ? this.serverMetadata.credential_endpoint : `${this.getIssuer()}/credential`;
  }

  private assertInitiation(): void {
    if (!this._initiation) {
      throw Error(`No issuance initiation present`);
    }
  }
}
