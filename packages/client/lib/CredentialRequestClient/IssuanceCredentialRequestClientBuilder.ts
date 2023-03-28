import {
  AccessTokenResponse,
  EndpointMetadata,
  IssuanceInitiationRequestPayload,
  IssuanceInitiationWithBaseUrl,
  OpenID4VCIServerMetadata,
} from '@sphereon/openid4vci-common';
import { CredentialFormat } from '@sphereon/ssi-types';

import { convertURIToJsonObject } from '../functions';

import { CredentialIssuanceRequestClientBuilder } from './CredentialIssuanceRequestClientBuilder';
import { CredentialRequestClient } from './CredentialRequestClient';

export class IssuanceCredentialRequestClientBuilder implements CredentialIssuanceRequestClientBuilder {
  credentialEndpoint?: string;
  credentialType?: string | string[];
  format?: CredentialFormat | CredentialFormat[];
  token?: string;

  public static fromIssuanceInitiationURI({ uri, metadata }: { uri: string; metadata?: EndpointMetadata }): IssuanceCredentialRequestClientBuilder {
    return IssuanceCredentialRequestClientBuilder.fromIssuanceInitiationRequest({
      request: convertURIToJsonObject(uri, {
        arrayTypeProperties: ['credential_type'],
        requiredProperties: ['issuer', 'credential_type'],
      }) as IssuanceInitiationRequestPayload,
      metadata,
    });
  }

  public static fromIssuanceInitiationRequest({
    request,
    metadata,
  }: {
    request: IssuanceInitiationRequestPayload;
    metadata?: EndpointMetadata;
  }): IssuanceCredentialRequestClientBuilder {
    const builder = new IssuanceCredentialRequestClientBuilder();
    builder.withCredentialEndpoint(
      metadata?.credential_endpoint
        ? metadata.credential_endpoint
        : request.issuer.endsWith('/')
        ? `${request.issuer}credential`
        : `${request.issuer}/credential`
    );

    //todo: This basically sets all types available during initiation. Probably the user only wants a subset. So do we want to do this?
    builder.withCredentialType(request.credential_type);

    return builder;
  }

  public static fromIssuanceInitiation({
    initiation,
    metadata,
  }: {
    initiation: IssuanceInitiationWithBaseUrl;
    metadata?: EndpointMetadata;
  }): IssuanceCredentialRequestClientBuilder {
    return IssuanceCredentialRequestClientBuilder.fromIssuanceInitiationRequest({
      request: initiation.issuanceInitiationRequest,
      metadata,
    });
  }

  public withCredentialEndpointFromMetadata(metadata: OpenID4VCIServerMetadata): IssuanceCredentialRequestClientBuilder {
    this.credentialEndpoint = metadata.credential_endpoint;
    return this;
  }

  public withCredentialEndpoint(credentialEndpoint: string): IssuanceCredentialRequestClientBuilder {
    this.credentialEndpoint = credentialEndpoint;
    return this;
  }

  public withCredentialType(credentialType: string | string[]): IssuanceCredentialRequestClientBuilder {
    this.credentialType = credentialType;
    return this;
  }

  public withFormat(format: CredentialFormat | CredentialFormat[]): IssuanceCredentialRequestClientBuilder {
    this.format = format;
    return this;
  }

  public withToken(accessToken: string): IssuanceCredentialRequestClientBuilder {
    this.token = accessToken;
    return this;
  }

  public withTokenFromResponse(response: AccessTokenResponse): IssuanceCredentialRequestClientBuilder {
    this.token = response.access_token;
    return this;
  }

  public build(): CredentialRequestClient {
    return new CredentialRequestClient(this);
  }
}
