import {
  CredentialOffer,
  CredentialOfferPayload,
  CredentialOfferPayloadV1_0_09,
  CredentialOfferRequestWithBaseUrl,
  CredentialOfferV1_0_11,
  determineSpecVersionFromURI,
  OpenId4VCIVersion,
  toUniformCredentialOfferRequest,
} from '@sphereon/oid4vci-common';
import Debug from 'debug';

import { convertJsonToURI, convertURIToJsonObject } from './functions';

const debug = Debug('sphereon:openid4vci:initiation');

export class CredentialOfferClient {
  public static async fromURI(uri: string, opts?: { resolve?: boolean }): Promise<CredentialOfferRequestWithBaseUrl> {
    debug(`Credential Offer URI: ${uri}`);
    if (!uri.includes('?') || !uri.includes('://')) {
      debug(`Invalid Credential Offer URI: ${uri}`);
      throw Error(`Invalid Credential Offer Request`);
    }
    const scheme = uri.split('://')[0];
    const baseUrl = uri.split('?')[0];
    const version = determineSpecVersionFromURI(uri);
    let credentialOffer: CredentialOffer;
    let credentialOfferPayload: CredentialOfferPayload;
    if (version < OpenId4VCIVersion.VER_1_0_11) {
      credentialOfferPayload = convertURIToJsonObject(uri, {
        arrayTypeProperties: ['credential_type'],
        requiredProperties: uri.includes('credential_offer_uri=') ? ['credential_offer_uri'] : ['issuer', 'credential_type'],
      }) as CredentialOfferPayloadV1_0_09;
      credentialOffer = {
        credential_offer: credentialOfferPayload,
      };
    } else {
      credentialOffer = convertURIToJsonObject(uri, {
        arrayTypeProperties: ['credentials'],
        requiredProperties: uri.includes('credential_offer_uri=') ? ['credential_offer_uri'] : ['credential_offer'],
      }) as CredentialOfferV1_0_11;
      if (credentialOffer?.credential_offer_uri === undefined && !credentialOffer?.credential_offer) {
        throw Error('Either a credential_offer or credential_offer_uri should be present in ' + uri);
      }
    }
    const request = await toUniformCredentialOfferRequest(credentialOffer, {
      ...opts,
      version,
    });

    return {
      scheme,
      baseUrl,
      ...request,
    };
  }

  public static toURI(
    requestWithBaseUrl: CredentialOfferRequestWithBaseUrl,
    opts?: {
      version?: OpenId4VCIVersion;
    }
  ): string {
    debug(`Credential Offer Request with base URL: ${JSON.stringify(requestWithBaseUrl)}`);
    const version = opts?.version ?? requestWithBaseUrl.version;
    let baseUrl = requestWithBaseUrl.baseUrl.includes(requestWithBaseUrl.scheme)
      ? requestWithBaseUrl.baseUrl
      : `${requestWithBaseUrl.scheme.replace('://', '')}://${requestWithBaseUrl.baseUrl}`;
    let param: string | undefined;

    const isUri = requestWithBaseUrl.credential_offer_uri !== undefined;

    if (version.valueOf() >= OpenId4VCIVersion.VER_1_0_11.valueOf()) {
      // v11 changed from encoding every param to a encoded json object with a credential_offer param key
      if (!baseUrl.includes('?')) {
        param = isUri ? 'credential_offer_uri' : 'credential_offer';
      } else {
        const split = baseUrl.split('?');
        if (split.length > 1 && split[1] !== '') {
          if (baseUrl.endsWith('&')) {
            param = isUri ? 'credential_offer_uri' : 'credential_offer';
          } else if (!baseUrl.endsWith('=')) {
            baseUrl += `&`;
            param = isUri ? 'credential_offer_uri' : 'credential_offer';
          }
        }
      }
    }
    return convertJsonToURI(requestWithBaseUrl.credential_offer_uri ?? requestWithBaseUrl.original_credential_offer, {
      baseUrl,
      arrayTypeProperties: isUri ? [] : ['credential_type'],
      uriTypeProperties: isUri
        ? ['credential_offer_uri']
        : version >= OpenId4VCIVersion.VER_1_0_11
        ? ['credential_issuer', 'credential_type']
        : ['issuer', 'credential_type'],
      param,
      version,
    });
  }
}
