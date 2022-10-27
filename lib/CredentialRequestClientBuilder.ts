import { CredentialFormat } from '@sphereon/ssi-types';

import { CredentialRequestClient } from './CredentialRequestClient';
import { convertURIToJsonObject } from './functions';
import {
  AccessTokenResponse,
  IssuanceInitiationRequestPayload,
  IssuanceInitiationWithBaseUrl,
  JWTSignerArgs,
  OID4VCIServerMetadata
} from './types';

export class CredentialRequestClientBuilder {
  credentialEndpoint: string;
  clientId: string;
  credentialType: string | string[];
  format: CredentialFormat | CredentialFormat[];
  jwtSignerArgs: JWTSignerArgs;
  token: string;

  public static fromIssuanceInitiationURI(issuanceInitiationURI: string, metadata?: OID4VCIServerMetadata): CredentialRequestClientBuilder {
    return CredentialRequestClientBuilder.fromIssuanceInitiationRequest(
      convertURIToJsonObject(issuanceInitiationURI, {
        arrayTypeProperties: ['credential_type'],
        requiredProperties: ['issuer', 'credential_type'],
      }) as IssuanceInitiationRequestPayload,
      metadata
    );
  }

  public static fromIssuanceInitiationRequest(
    issuanceInitiationRequest: IssuanceInitiationRequestPayload,
    metadata?: OID4VCIServerMetadata
  ): CredentialRequestClientBuilder {
    const builder = new CredentialRequestClientBuilder();
    builder.withCredentialEndpoint(metadata?.credential_endpoint ? metadata.credential_endpoint : issuanceInitiationRequest.issuer);

    //todo: This basically sets all types available during initiation. Probably the user only wants a subset. So do we want to do this?
    builder.withCredentialType(issuanceInitiationRequest.credential_type);

    return builder;
  }

  public static fromIssuanceInitiation(
    issuanceInitiation: IssuanceInitiationWithBaseUrl,
    metadata?: OID4VCIServerMetadata
  ): CredentialRequestClientBuilder {
    return CredentialRequestClientBuilder.fromIssuanceInitiationRequest(issuanceInitiation.issuanceInitiationRequest, metadata);
  }

  public withCredentialEndpointFromMetadata(metadata: OID4VCIServerMetadata): CredentialRequestClientBuilder {
    this.credentialEndpoint = metadata.credential_endpoint;
    return this;
  }

  public withCredentialEndpoint(credentialRequestUrl: string): CredentialRequestClientBuilder {
    this.credentialEndpoint = credentialRequestUrl;
    return this;
  }

  public withCredentialType(credentialType: string | string[]): CredentialRequestClientBuilder {
    this.credentialType = credentialType;
    return this;
  }

  public withFormat(format: CredentialFormat | CredentialFormat[]): CredentialRequestClientBuilder {
    this.format = format;
    return this;
  }

  public withClientId(clientId: string): CredentialRequestClientBuilder {
    this.clientId = clientId;
    return this;
  }

  public withJWTSignerArgs(jwtSignerArgs: JWTSignerArgs): CredentialRequestClientBuilder {
    this.jwtSignerArgs = jwtSignerArgs;
    return this;
  }

  public withToken(accessToken: string): CredentialRequestClientBuilder {
    this.token = accessToken;
    return this;
  }

  public withTokenFromResponse(response: AccessTokenResponse): CredentialRequestClientBuilder {
    this.token = response.access_token;
    return this;
  }

  public build(): CredentialRequestClient {
    return new CredentialRequestClient(this);
  }
}
