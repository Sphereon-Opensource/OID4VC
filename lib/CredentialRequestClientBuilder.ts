import { CredentialFormat } from '@sphereon/ssi-types';

import { CredentialRequestClient } from './CredentialRequestClient';
import { convertURIToJsonObject } from './functions';
import { IssuanceInitiationRequestPayload, IssuanceInitiationWithBaseUrl } from './types';

export class CredentialRequestClientBuilder {
  issuerURL: string;
  clientId: string;
  credentialType: string | string[];
  format: CredentialFormat | CredentialFormat[];

  public static fromIssuanceInitiationURI(issuanceInitiation: string): CredentialRequestClientBuilder {
    return CredentialRequestClientBuilder.fromIssuanceInitiationRequest(
      convertURIToJsonObject(issuanceInitiation, {
        arrayTypeProperties: ['credential_type'],
        requiredProperties: ['issuer', 'credential_type'],
      }) as IssuanceInitiationRequestPayload
    );
  }

  public static fromIssuanceInitiationRequest(issuanceInitiationRequest: IssuanceInitiationRequestPayload): CredentialRequestClientBuilder {
    const builder = new CredentialRequestClientBuilder();
    builder.withIssuerURL(issuanceInitiationRequest.issuer);
    builder.withCredentialType(issuanceInitiationRequest.credential_type);

    return builder;
  }

  public static fromIssuanceInitiation(issuanceInitiation: IssuanceInitiationWithBaseUrl): CredentialRequestClientBuilder {
    return CredentialRequestClientBuilder.fromIssuanceInitiationRequest(issuanceInitiation.issuanceInitiationRequest);
  }

  public withIssuerURL(credentialRequestUrl: string): CredentialRequestClientBuilder {
    this.issuerURL = credentialRequestUrl;
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

  public build(): CredentialRequestClient {
    return new CredentialRequestClient(this);
  }
}
