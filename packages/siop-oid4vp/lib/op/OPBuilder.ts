import { EventEmitter } from 'events'

import { HasherSync, IIssuerId } from '@sphereon/ssi-types'

import { PropertyTargets } from '../authorization-request'
import { PresentationSignCallback } from '../authorization-response'
import { CreateJwtCallback, ResponseIss, ResponseMode, ResponseRegistrationOpts, SupportedVersion, VerifyJwtCallback } from '../types'

import { OP } from './OP'

export class OPBuilder {
  expiresIn?: number
  issuer?: IIssuerId | ResponseIss
  responseMode?: ResponseMode = ResponseMode.DIRECT_POST
  responseRegistration?: Partial<ResponseRegistrationOpts> = {}
  createJwtCallback?: CreateJwtCallback
  verifyJwtCallback?: VerifyJwtCallback
  presentationSignCallback?: PresentationSignCallback
  supportedVersions?: SupportedVersion[]
  eventEmitter?: EventEmitter

  hasher?: HasherSync

  withHasher(hasher: HasherSync): OPBuilder {
    this.hasher = hasher

    return this
  }

  withIssuer(issuer: ResponseIss | string): OPBuilder {
    this.issuer = issuer
    return this
  }

  withExpiresIn(expiresIn: number): OPBuilder {
    this.expiresIn = expiresIn
    return this
  }

  withResponseMode(responseMode: ResponseMode): OPBuilder {
    this.responseMode = responseMode
    return this
  }

  withRegistration(responseRegistration: ResponseRegistrationOpts, targets?: PropertyTargets): OPBuilder {
    this.responseRegistration = {
      targets,
      ...responseRegistration,
    }
    return this
  }

  /*//TODO registration object creation
  authorizationEndpoint?: Schema.OPENID | string;
  scopesSupported?: Scope[] | Scope;
  subjectTypesSupported?: SubjectType[] | SubjectType;
  idTokenSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
  requestObjectSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
*/

  withCreateJwtCallback(createJwtCallback: CreateJwtCallback): OPBuilder {
    this.createJwtCallback = createJwtCallback
    return this
  }

  withVerifyJwtCallback(verifyJwtCallback: VerifyJwtCallback): OPBuilder {
    this.verifyJwtCallback = verifyJwtCallback
    return this
  }

  withSupportedVersions(supportedVersions: SupportedVersion[] | SupportedVersion | string[] | string): OPBuilder {
    const versions = Array.isArray(supportedVersions) ? supportedVersions : [supportedVersions]
    for (const version of versions) {
      this.addSupportedVersion(version)
    }
    return this
  }

  addSupportedVersion(supportedVersion: string | SupportedVersion): OPBuilder {
    if (!this.supportedVersions) {
      this.supportedVersions = []
    }
    if (typeof supportedVersion === 'string') {
      this.supportedVersions.push(SupportedVersion[supportedVersion])
    } else {
      this.supportedVersions.push(supportedVersion)
    }
    return this
  }

  withPresentationSignCallback(presentationSignCallback: PresentationSignCallback): OPBuilder {
    this.presentationSignCallback = presentationSignCallback
    return this
  }

  withEventEmitter(eventEmitter?: EventEmitter): OPBuilder {
    this.eventEmitter = eventEmitter ?? new EventEmitter()
    return this
  }

  build(): OP {
    /*if (!this.responseRegistration) {
      throw Error('You need to provide response registrations values')
    } else */ /*if (!this.withSignature) {
      throw Error('You need to supply withSignature values');
    } else */ if (!this.supportedVersions || this.supportedVersions.length === 0) {
      this.supportedVersions = [SupportedVersion.SIOPv2_D11, SupportedVersion.SIOPv2_ID1, SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1]
    }
    // We ignore the private visibility, as we don't want others to use the OP directly
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    return new OP({ builder: this })
  }
}
