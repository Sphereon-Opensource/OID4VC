import { CredentialFormat } from '@sphereon/ssi-types';
import Debug from 'debug';
import { CredentialRequestClientBuilder } from '../dist/main';
import { AccessTokenClient } from './AccessTokenClient';
import { IssuanceInitiation } from './IssuanceInitiation';
import { MetadataClient } from './MetadataClient';
import {
  AccessTokenRequestOpts,
  AccessTokenResponse,
  AuthzFlowType,
  EndpointMetadata,
  IssuanceInitiationWithBaseUrl,
  ProofOfPossession,
  ProofOfPossessionArgs
} from './types';

const debug = Debug('sphereon:openid4vci:flow');

export class OpenID4VCIClient {
  private readonly _flowType: AuthzFlowType;
  private readonly _initiation: IssuanceInitiationWithBaseUrl;
  private _serverMetadata: EndpointMetadata;
  private _accessToken: AccessTokenResponse;

  private constructor(initiation: IssuanceInitiationWithBaseUrl, flowType: AuthzFlowType) {
    if (flowType !== AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW) {
      throw new Error(`Only pre-authorized code flow is support at present`);
    }
    this._flowType = flowType;
    this._initiation = initiation;

  }

  public static async initiateFromURI(issuanceInitiationURI: string, flowType: AuthzFlowType, opts?: { retrieveServerMetadata: boolean }): Promise<OpenID4VCIClient> {
    const flow = new OpenID4VCIClient(IssuanceInitiation.fromURI(issuanceInitiationURI), flowType);
    if (!opts || opts.retrieveServerMetadata !== false) {
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

  public async acquireAccessToken(opts?: Omit<AccessTokenRequestOpts, 'metadata'>): Promise<AccessTokenResponse> {
    this.assertInitiation();
    if (!this._accessToken) {
      const accessTokenClient = new AccessTokenClient();
      const response = await accessTokenClient.acquireAccessTokenUsingIssuanceInitiation(this._initiation, { metadata: this._serverMetadata, ...opts });
      if (response.errorBody) {
        debug(`Access token error:\r\n${response.errorBody}`);
        throw Error(`Retrieving an access token from ${this._serverMetadata.token_endpoint} for issuer ${this._initiation.issuanceInitiationRequest.issuer} failed with status: ${response.origResponse.status}`);
      }
      this._accessToken = response.successBody;
    }
    return this._accessToken;
  }

  public async acquireCredentials(proof: ProofOfPossession | ProofOfPossessionArgs, credentialType: string | string[], opts?: { clientId?: string; format?: CredentialFormat | CredentialFormat[]; }) {
    const builder = CredentialRequestClientBuilder.fromIssuanceInitiation(this.initiation, this.serverMetadata);
    builder.withClientId(opts?.clientId);
    if (this.serverMetadata?.openid4vci_metadata) {
      const metadata = this.serverMetadata.openid4vci_metadata;
      const types = Array.isArray(credentialType) ? credentialType : [credentialType];
      if (types.some(type => !metadata.credentials_supported || !metadata.credentials_supported[type])) {
        throw Error(`Not all credential types ${JSON.stringify(credentialType)} are supported by issuer ${this.getIssuer()}`);
      }
      // todo: Format check? We might end up with some disjoint type / format combinations supported by the server
    }
    const credentialRequestClient = builder.build()
    return await credentialRequestClient.acquireCredentialsUsingProof(proof, {credentialType ,...opts})
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

  get accessToken(): AccessTokenResponse {
    return this._accessToken;
  }

  public getIssuer(): string {
    this.assertInitiation()
    return this._serverMetadata ? this.serverMetadata.issuer : this.initiation.issuanceInitiationRequest.issuer;
  }

  public getAccessTokenEndpoint(): string {
    this.assertInitiation()
    return this.serverMetadata ? this.serverMetadata.token_endpoint : AccessTokenClient.determineTokenURL({}, {issuer: this.getIssuer()})
  }

  public getCredentialEndpoint(): string {
    this.assertInitiation()
    return this.serverMetadata ? this.serverMetadata.credential_endpoint :  `${this.getIssuer()}/credential`
  }


  private assertInitiation() {
    if (!this._initiation) {
      throw Error(`No issuance initiation present`);
    }
  }
}
