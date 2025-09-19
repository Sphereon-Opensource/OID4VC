import { JwtIssuer } from '@sphereon/oid4vc-common'
import { PresentationSignCallBackParams } from '@sphereon/pex'
import { Format } from '@sphereon/pex-models'
import {
  CompactSdJwtVc,
  HasherSync,
  MdocOid4vpIssuerSigned,
  PresentationSubmission,
  W3CVerifiablePresentation,
} from '@sphereon/ssi-types'
import { DcqlQuery } from 'dcql'
import { AuthorizationResponse } from './AuthorizationResponse'
import {
  CreateJwtCallback,
  ResponseMode,
  ResponseRegistrationOpts,
  ResponseType,
  ResponseURIType,
  SupportedVersion,
  VerifiablePresentationWithFormat,
  Verification,
  VerifyJwtCallback,
  ResponseIss
} from '../types'

export interface AuthorizationResponseOpts {
  responseURI?: string // This is either the redirect URI or response URI. See also responseURIType. response URI is used when response_mode is `direct_post`
  responseURIType?: ResponseURIType
  registration?: ResponseRegistrationOpts
  version?: SupportedVersion
  audience?: string
  createJwtCallback: CreateJwtCallback
  jwtIssuer?: JwtIssuer
  responseMode?: ResponseMode
  responseType?: [ResponseType]
  expiresIn?: number
  accessToken?: string
  tokenType?: string
  refreshToken?: string
  dcqlResponse?: DcqlResponseOpts
  isFirstParty?: boolean
}

export interface DcqlResponseOpts {
  dcqlPresentation: Record<string, string | Record<string, unknown> | Array<string | Record<string, unknown>>>
}

export interface DcqlQueryPayloadOpts {
  dcql_query: string
}

export interface VerifiablePresentationWithSubmissionData extends VerifiablePresentationWithFormat {
  vpTokenLocation: VPTokenLocation
  submissionData: PresentationSubmission
}

export enum VPTokenLocation {
  AUTHORIZATION_RESPONSE = 'authorization_response',
  ID_TOKEN = 'id_token',
  TOKEN_RESPONSE = 'token_response',
}

export type PresentationVerificationResult = { verified: boolean; reason?: string }

export type PresentationVerificationCallback = (
  args: W3CVerifiablePresentation | CompactSdJwtVc | MdocOid4vpIssuerSigned,
  presentationSubmission?: PresentationSubmission,
) => Promise<PresentationVerificationResult>

export type PresentationSignCallback = (args: PresentationSignCallBackParams) => Promise<W3CVerifiablePresentation | CompactSdJwtVc>

export interface VerifyAuthorizationResponseOpts {
  correlationId: string
  verification: Verification
  verifyJwtCallback: VerifyJwtCallback
  hasher?: HasherSync
  nonce?: string // To verify the response against the supplied nonce
  state?: string // To verify the response against the supplied state
  dcqlQuery?: DcqlQuery
  audience?: string // The audience/redirect_uri
  restrictToFormats?: Format // Further restrict to certain VC formats, not expressed in the presentation definition
  restrictToDIDMethods?: string[]
}

export interface AuthorizationResponseWithCorrelationId {
  // The URI to send the response to. Can be derived from either the redirect_uri or the response_uri
  responseURI: string
  response: AuthorizationResponse
  correlationId: string
}

export interface CreateAuthorizationResponseOpts {
  jwtIssuer?: JwtIssuer
  version?: SupportedVersion
  correlationId?: string
  audience?: string
  issuer?: ResponseIss | string
  verification?: Verification
  dcqlResponse?: DcqlResponseOpts
  isFirstParty?: boolean
}
