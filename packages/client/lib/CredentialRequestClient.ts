import {
  CredentialOfferFormat,
  CredentialRequestV1_0_08,
  CredentialResponse,
  CredentialSupported,
  CredentialSupportedJwtVcJsonLdAndLdpVc,
  getFormatForVersion,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
  OpenIDResponse,
  ProofOfPossession,
  UniformCredentialRequest,
  URL_NOT_VALID,
} from '@sphereon/oid4vci-common';
import { CredentialFormat } from '@sphereon/ssi-types';
import Debug from 'debug';

import { CredentialRequestClientBuilder } from './CredentialRequestClientBuilder';
import { ProofOfPossessionBuilder } from './ProofOfPossessionBuilder';
import { isValidURL, post } from './functions';

const debug = Debug('sphereon:oid4vci:credential');

export interface CredentialRequestOpts {
  credentialEndpoint: string;
  proof: ProofOfPossession;
  token: string;
  version: OpenId4VCIVersion;
}

export interface RequestFromCredentialSupported {
  credentialSupported: { id: string; format: OID4VCICredentialFormat | CredentialFormat | string } | CredentialSupported;
}

export interface RequestFromInlineCredentialOffer {
  inlineCredentialOffer: CredentialOfferFormat;
}

export interface RequestFromRequestInput {
  requestInput: UniformCredentialRequest & { proof?: never };
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

  public async acquireCredentialsUsingProof(
    opts: { proofInput: ProofOfPossessionBuilder | ProofOfPossession } & (
      | RequestFromCredentialSupported
      | RequestFromInlineCredentialOffer
      | RequestFromRequestInput
    )
  ): Promise<OpenIDResponse<CredentialResponse>> {
    // Get request based on credential offer or credentialSupported.
    const request =
      // inline credential offer
      'inlineCredentialOffer' in opts
        ? await this.createCredentialRequestFromInlineOffer(opts)
        : // credential supported
        'credentialSupported' in opts
        ? await this.createCredentialRequestFromCredentialSupported(opts)
        : // direct request input
          await this.createCredentialRequest(opts);

    return await this.acquireCredentialsUsingRequest(request);
  }

  public async acquireCredentialsUsingRequest(
    request: UniformCredentialRequest | CredentialRequestV1_0_08
  ): Promise<OpenIDResponse<CredentialResponse>> {
    // If the version is below draft 11, the request also needs to be a CredentialRequestV1_0_08
    if (this.version() === OpenId4VCIVersion.VER_1_0_08 && !('type' in request)) {
      throw new Error(
        `Missing required 'type' property in credential request. Make sure to provide a 'CredentialRequestV1_0_08' object when version is draft 8`
      );
    }

    const credentialEndpoint: string = this.credentialRequestOpts.credentialEndpoint;
    if (!isValidURL(credentialEndpoint)) {
      debug(`Invalid credential endpoint: ${credentialEndpoint}`);
      throw new Error(URL_NOT_VALID);
    }
    debug(`Acquiring credential(s) from: ${credentialEndpoint}`);
    const requestToken = this.credentialRequestOpts.token;
    const response: OpenIDResponse<CredentialResponse> = await post(credentialEndpoint, JSON.stringify(request), { bearerToken: requestToken });
    debug(`Credential endpoint ${credentialEndpoint} response:\r\n${response}`);
    return response;
  }

  public async createCredentialRequestFromInlineOffer(
    opts: { proofInput: ProofOfPossessionBuilder | ProofOfPossession } & RequestFromInlineCredentialOffer
  ): Promise<UniformCredentialRequest> {
    const { inlineCredentialOffer } = opts;

    if (!this.isV9OrHigher()) {
      throw new Error('Inline credential offers are only supported for draft 9 and higher');
    }

    // Transform the inline offer into a credential request
    if (inlineCredentialOffer.format === 'jwt_vc_json') {
      return {
        format: inlineCredentialOffer.format,
        types: inlineCredentialOffer.types,
        proof: await this.buildProof(opts.proofInput),
      };
    } else if (inlineCredentialOffer.format === 'jwt_vc_json-ld' || inlineCredentialOffer.format === 'ldp_vc') {
      return {
        format: inlineCredentialOffer.format,
        credential_definition: inlineCredentialOffer.credential_definition,
        proof: await this.buildProof(opts.proofInput),
      };
    } else {
      throw new Error(`Unsupported credential offer format: ${inlineCredentialOffer.format}`);
    }
  }

  public async createCredentialRequestFromCredentialSupported(
    opts: { proofInput: ProofOfPossessionBuilder | ProofOfPossession } & RequestFromCredentialSupported
  ): Promise<UniformCredentialRequest | CredentialRequestV1_0_08> {
    const { credentialSupported } = opts;

    const format = getFormatForVersion(credentialSupported.format, this.version());

    if (!this.isV9OrHigher()) {
      // Below v9, the `id` is required as it must be passed in the request
      if (typeof credentialSupported.id !== 'string') {
        throw new Error(`Missing required credential supported id for versions below draft 9`);
      }

      // Remove the suffix from the id that is added by us when multiple formats for a supported credential exist
      // this is behavior to make the API of draft 11 align with the API of lower versions
      if (credentialSupported.id.endsWith(`-${credentialSupported.format}`)) {
        credentialSupported.id = credentialSupported.id.replace(`-${credentialSupported.format}`, '');
      }

      return {
        format,
        type: credentialSupported.id,
        proof: await this.buildProof(opts.proofInput),
      } satisfies CredentialRequestV1_0_08;
    }

    // We require the credential supported
    if (!('types' in credentialSupported)) {
      throw new Error(`Missing required 'types' property in credential supported. Make sure to provide a 'CredentialSupported' object`);
    }

    // Transform the credential supported into a credential request
    if (format === 'jwt_vc_json') {
      return {
        format: 'jwt_vc_json',
        types: credentialSupported.types,
        proof: await this.buildProof(opts.proofInput),
      } satisfies UniformCredentialRequest;
    } else if (format === 'jwt_vc_json-ld' || format === 'ldp_vc') {
      const supported = credentialSupported as CredentialSupportedJwtVcJsonLdAndLdpVc;
      return {
        format,
        credential_definition: {
          '@context': supported['@context'],
          types: credentialSupported.types,
        },
      } satisfies UniformCredentialRequest;
    } else {
      throw new Error(`Unsupported credential supported format: ${credentialSupported.format}`);
    }
  }

  public async createCredentialRequest(
    opts: {
      proofInput: ProofOfPossessionBuilder | ProofOfPossession;
    } & RequestFromRequestInput
  ): Promise<UniformCredentialRequest> {
    const { requestInput } = opts;

    if (!this.isV9OrHigher()) {
      throw new Error(
        'Creating credential request directly is only supported for versions using draft 9 and higher. Use `createCredentialRequestFromCredentialSupported` for lower versions'
      );
    }

    return {
      ...requestInput,
      proof: await this.buildProof(opts.proofInput),
    };
  }

  private async buildProof(proofInput: ProofOfPossessionBuilder | ProofOfPossession): Promise<ProofOfPossession> {
    const proof =
      'proof_type' in proofInput ? await ProofOfPossessionBuilder.fromProof(proofInput, this.version()).build() : await proofInput.build();

    return proof;
  }

  private version(): OpenId4VCIVersion {
    return this.credentialRequestOpts?.version ?? OpenId4VCIVersion.VER_1_0_11;
  }

  private isV9OrHigher(): boolean {
    return this.version() >= OpenId4VCIVersion.VER_1_0_09;
  }
}
