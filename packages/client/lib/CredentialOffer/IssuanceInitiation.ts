import {EndpointMetadata, IssuanceInitiationRequestPayload, IssuanceInitiationWithBaseUrl} from '@sphereon/openid4vci-common';
import Debug from 'debug';

import { convertJsonToURI, convertURIToJsonObject } from '../functions';
import {CredentialOfferStrategy} from "./index";
import {MetadataClient} from "../MetadataClient";
import {CredentialRequestClientBuilder} from "../CredentialRequestClientBuilder";

const debug = Debug('sphereon:openid4vci:initiation');
export class IssuanceInitiation implements CredentialOfferStrategy {

  public getCredentialOffer(issuanceInitiationURI: string) : IssuanceInitiationWithBaseUrl {
    return IssuanceInitiation.fromURI(issuanceInitiationURI);
  }

  public static fromURI(issuanceInitiationURI: string): IssuanceInitiationWithBaseUrl {
    debug(`issuance initiation URI: ${issuanceInitiationURI}`);
    if (!issuanceInitiationURI.includes('?')) {
      debug(`Invalid issuance initiation URI: ${issuanceInitiationURI}`);
      throw new Error('Invalid Issuance Initiation Request Payload');
    }
    const baseUrl = issuanceInitiationURI.split('?')[0];
    const credentialOfferPayload = convertURIToJsonObject(issuanceInitiationURI, {
      arrayTypeProperties: ['credential_type'],
      requiredProperties: ['issuer', 'credential_type'],
    }) as IssuanceInitiationRequestPayload;

    return {
      baseUrl,
      credentialOfferPayload,
    };
  }

  public static toURI(issuanceInitiation: IssuanceInitiationWithBaseUrl): string {
    let credentialOfferPayload = issuanceInitiation.credentialOfferPayload as IssuanceInitiationRequestPayload;
    return convertJsonToURI(credentialOfferPayload, {
      baseUrl: issuanceInitiation.baseUrl,
      arrayTypeProperties: ['credential_type'],
      uriTypeProperties: ['issuer', 'credential_type'],
    });
  }

  public async getServerMetaData(issuanceInitiation: IssuanceInitiationWithBaseUrl): Promise<EndpointMetadata> {
    const {issuer} = issuanceInitiation.credentialOfferPayload as IssuanceInitiationRequestPayload;
    return await MetadataClient.retrieveAllMetadata(issuer);
  }

  public getCredentialTypes(issuanceInitiation: IssuanceInitiationWithBaseUrl): string[] {
    let credentialOfferPayload = issuanceInitiation.credentialOfferPayload as IssuanceInitiationRequestPayload;
    return typeof credentialOfferPayload.credential_type === 'string'
        ? [credentialOfferPayload.credential_type]
        : credentialOfferPayload.credential_type;
  }

  public getIssuer(issuanceInitiation: IssuanceInitiationWithBaseUrl): string {
    return (issuanceInitiation.credentialOfferPayload as IssuanceInitiationRequestPayload).issuer;
  }

  public getCredentialRequestClientBuilder(
    credentialOfferPayload: IssuanceInitiationRequestPayload,
    metadata?: EndpointMetadata): CredentialRequestClientBuilder {
    return CredentialRequestClientBuilder.fromIssuanceInitiationRequest({
      request: credentialOfferPayload,
      metadata,
    });
  }
}
