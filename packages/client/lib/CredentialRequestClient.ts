import {
  CredentialResponse,
  getCredentialRequestForVersion,
  getUniformFormat,
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
  credentialTypes: string[];
  format?: CredentialFormat | OID4VCICredentialFormat;
  proof: ProofOfPossession;
  token: string;
  version: OpenId4VCIVersion;
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

  public async acquireCredentialsUsingProof<DIDDoc>(opts: {
    proofInput: ProofOfPossessionBuilder<DIDDoc> | ProofOfPossession;
    credentialTypes?: string | string[];
    format?: CredentialFormat | OID4VCICredentialFormat;
  }): Promise<OpenIDResponse<CredentialResponse>> {
    const { credentialTypes, proofInput, format } = opts;

    const request = await this.createCredentialRequest({ proofInput, credentialTypes, format, version: this.version() });
    return await this.acquireCredentialsUsingRequest(request);
  }

  public async acquireCredentialsUsingRequest(uniformRequest: UniformCredentialRequest): Promise<OpenIDResponse<CredentialResponse>> {
    const request = getCredentialRequestForVersion(uniformRequest, this.version());
    const credentialEndpoint: string = this.credentialRequestOpts.credentialEndpoint;
    if (!isValidURL(credentialEndpoint)) {
      debug(`Invalid credential endpoint: ${credentialEndpoint}`);
      throw new Error(URL_NOT_VALID);
    }
    debug(`Acquiring credential(s) from: ${credentialEndpoint}`);
    const requestToken: string = this.credentialRequestOpts.token;
    const response: OpenIDResponse<CredentialResponse> = await post(credentialEndpoint, JSON.stringify(request), { bearerToken: requestToken });
    debug(`Credential endpoint ${credentialEndpoint} response:\r\n${response}`);
    return response;
  }

  public async createCredentialRequest<DIDDoc>(opts: {
    proofInput: ProofOfPossessionBuilder<DIDDoc> | ProofOfPossession;
    credentialTypes?: string | string[];
    format?: CredentialFormat | OID4VCICredentialFormat;
    version: OpenId4VCIVersion;
  }): Promise<UniformCredentialRequest> {
    const { proofInput } = opts;
    const formatSelection = opts.format ?? this.credentialRequestOpts.format;

    if (!formatSelection) {
      throw Error(`Format of credential to be issued is missing`);
    }
    const format = getUniformFormat(formatSelection);
    const typesSelection =
      opts?.credentialTypes && (typeof opts.credentialTypes === 'string' || opts.credentialTypes.length > 0)
        ? opts.credentialTypes
        : this.credentialRequestOpts.credentialTypes;
    const types = Array.isArray(typesSelection) ? typesSelection : [typesSelection];
    if (types.length === 0) {
      throw Error(`Credential type(s) need to be provided`);
    }
    // FIXME: this is mixing up the type (as id) from v8/v9 and the types (from the vc.type) from v11
    else if (!this.isV11OrHigher() && types.length !== 1) {
      throw Error('Only a single credential type is supported for V8/V9');
    }

    const proof =
      'proof_type' in proofInput
        ? await ProofOfPossessionBuilder.fromProof(proofInput as ProofOfPossession, opts.version).build()
        : await proofInput.build();

    // TODO: we should move format specific logic
    if (format === 'jwt_vc_json') {
      return {
        types,
        format,
        proof,
      };
    } else if (format === 'jwt_vc_json-ld' || format === 'ldp_vc') {
      return {
        format,
        proof,
        credential_definition: {
          types,
          // FIXME: this was not included in the original code, but it is required
          '@context': [],
        },
      };
    } else if (format === 'vc+sd-jwt') {
      if (types.length > 1) {
        throw Error(`Only a single credential type is supported for ${format}`);
      }

      return {
        format,
        proof,
        credential_definition: {
          vct: types[0],
        },
      };
    }

    throw new Error(`Unsupported format: ${format}`);
  }

  private version(): OpenId4VCIVersion {
    return this.credentialRequestOpts?.version ?? OpenId4VCIVersion.VER_1_0_11;
  }

  private isV11OrHigher(): boolean {
    return this.version() >= OpenId4VCIVersion.VER_1_0_11;
  }
}
