import { EventEmitter } from 'events';

import { Config, getUniResolver, UniResolver } from '@sphereon/did-uni-client';
import { Hasher, IIssuerId } from '@sphereon/ssi-types';
import { VerifyCallback } from '@sphereon/wellknown-dids-client';
import { Signer } from 'did-jwt';
import { Resolvable, Resolver } from 'did-resolver';

import { PropertyTargets } from '../authorization-request';
import { PresentationSignCallback } from '../authorization-response';
import { getMethodFromDid } from '../did';
import {
  CheckLinkedDomain,
  EcdsaSignature,
  ExternalSignature,
  InternalSignature,
  ResponseIss,
  ResponseMode,
  ResponseRegistrationOpts,
  SigningAlgo,
  SubjectSyntaxTypesSupportedValues,
  SuppliedSignature,
  SupportedVersion,
} from '../types';

import { OP } from './OP';

export class OPBuilder {
  expiresIn?: number;
  issuer?: IIssuerId | ResponseIss;
  resolvers: Map<string, Resolvable> = new Map<string, Resolvable>();
  responseMode?: ResponseMode = ResponseMode.DIRECT_POST;
  responseRegistration?: Partial<ResponseRegistrationOpts> = {};
  customResolver?: Resolvable;
  signature?: InternalSignature | ExternalSignature | SuppliedSignature;
  checkLinkedDomain?: CheckLinkedDomain;
  wellknownDIDVerifyCallback?: VerifyCallback;
  presentationSignCallback?: PresentationSignCallback;
  supportedVersions?: SupportedVersion[];
  eventEmitter?: EventEmitter;

  hasher?: Hasher;

  addDidMethod(didMethod: string, opts?: { resolveUrl?: string; baseUrl?: string }): OPBuilder {
    const method = didMethod.startsWith('did:') ? getMethodFromDid(didMethod) : didMethod;
    if (method === SubjectSyntaxTypesSupportedValues.DID.valueOf()) {
      opts ? this.addResolver('', new UniResolver({ ...opts } as Config)) : this.addResolver('', null);
    }
    opts ? this.addResolver(method, new Resolver(getUniResolver(method, { ...opts }))) : this.addResolver(method, null);
    return this;
  }

  withHasher(hasher: Hasher): OPBuilder {
    this.hasher = hasher;

    return this;
  }

  withIssuer(issuer: ResponseIss | string): OPBuilder {
    this.issuer = issuer;
    return this;
  }

  withCustomResolver(resolver: Resolvable): OPBuilder {
    this.customResolver = resolver;
    return this;
  }

  addResolver(didMethod: string, resolver: Resolvable): OPBuilder {
    const qualifiedDidMethod = didMethod.startsWith('did:') ? getMethodFromDid(didMethod) : didMethod;
    this.resolvers.set(qualifiedDidMethod, resolver);
    return this;
  }

  /*withDid(did: string): OPBuilder {
    this.did = did;
    return this;
  }
*/
  withExpiresIn(expiresIn: number): OPBuilder {
    this.expiresIn = expiresIn;
    return this;
  }

  withCheckLinkedDomain(mode: CheckLinkedDomain): OPBuilder {
    this.checkLinkedDomain = mode;
    return this;
  }

  withResponseMode(responseMode: ResponseMode): OPBuilder {
    this.responseMode = responseMode;
    return this;
  }

  withRegistration(responseRegistration: ResponseRegistrationOpts, targets?: PropertyTargets): OPBuilder {
    this.responseRegistration = {
      targets,
      ...responseRegistration,
    };
    return this;
  }

  /*//TODO registration object creation
  authorizationEndpoint?: Schema.OPENID | string;
  scopesSupported?: Scope[] | Scope;
  subjectTypesSupported?: SubjectType[] | SubjectType;
  idTokenSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
  requestObjectSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
*/

  // Only internal and supplied signatures supported for now
  withSignature(signature: InternalSignature | SuppliedSignature): OPBuilder {
    this.signature = signature;
    return this;
  }

  withInternalSignature(hexPrivateKey: string, did: string, kid: string, alg: SigningAlgo, customJwtSigner?: Signer): OPBuilder {
    this.withSignature({ hexPrivateKey, did, kid, alg, customJwtSigner });
    return this;
  }

  withSuppliedSignature(
    signature: (data: string | Uint8Array) => Promise<EcdsaSignature | string>,
    did: string,
    kid: string,
    alg: SigningAlgo,
  ): OPBuilder {
    this.withSignature({ signature, did, kid, alg });
    return this;
  }

  withWellknownDIDVerifyCallback(wellknownDIDVerifyCallback: VerifyCallback): OPBuilder {
    this.wellknownDIDVerifyCallback = wellknownDIDVerifyCallback;
    return this;
  }

  withSupportedVersions(supportedVersions: SupportedVersion[] | SupportedVersion | string[] | string): OPBuilder {
    const versions = Array.isArray(supportedVersions) ? supportedVersions : [supportedVersions];
    for (const version of versions) {
      this.addSupportedVersion(version);
    }
    return this;
  }

  addSupportedVersion(supportedVersion: string | SupportedVersion): OPBuilder {
    if (!this.supportedVersions) {
      this.supportedVersions = [];
    }
    if (typeof supportedVersion === 'string') {
      this.supportedVersions.push(SupportedVersion[supportedVersion]);
    } else {
      this.supportedVersions.push(supportedVersion);
    }
    return this;
  }

  withPresentationSignCallback(presentationSignCallback: PresentationSignCallback): OPBuilder {
    this.presentationSignCallback = presentationSignCallback;
    return this;
  }

  withEventEmitter(eventEmitter?: EventEmitter): OPBuilder {
    this.eventEmitter = eventEmitter ?? new EventEmitter();
    return this;
  }

  build(): OP {
    /*if (!this.responseRegistration) {
      throw Error('You need to provide response registrations values')
    } else */ /*if (!this.withSignature) {
      throw Error('You need to supply withSignature values');
    } else */ if (!this.supportedVersions || this.supportedVersions.length === 0) {
      this.supportedVersions = [SupportedVersion.SIOPv2_D11, SupportedVersion.SIOPv2_ID1, SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1];
    }
    // We ignore the private visibility, as we don't want others to use the OP directly
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    return new OP({ builder: this });
  }
}
