import { createDPoP, CreateDPoPClientOpts, getCreateDPoPOptions } from '@sphereon/oid4vc-common'
import {
  acquireDeferredCredential,
  AuthorizationDetailsV1_0_15,
  AuthorizationDetailsV1_0,
  CredentialRequest,
  CredentialRequestV1_0_15,
  CredentialRequestV1_0,
  CredentialResponse,
  DPoPResponseParams,
  ExperimentalSubjectIssuance,
  isDeferredCredentialResponse,
  isValidURL,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
  OpenIDResponse,
  post,
  ProofOfPossession,
  supportedOID4VCICredentialFormat,
  URL_NOT_VALID,
} from '@sphereon/oid4vci-common'
import { CredentialFormat, Loggers } from '@sphereon/ssi-types'

import { CredentialRequestClientBuilderV1_0_15 } from './CredentialRequestClientBuilderV1_0_15'
import { CredentialRequestClientBuilderV1_0 } from './CredentialRequestClientBuilderV1_0'
import { ProofOfPossessionBuilder } from './ProofOfPossessionBuilder'
import { shouldRetryResourceRequestWithDPoPNonce } from './functions/dpopUtil'

const logger = Loggers.DEFAULT.get('sphereon:oid4vci:credential')

export interface CredentialRequestOpts {
  deferredCredentialAwait?: boolean
  deferredCredentialIntervalInMS?: number
  credentialEndpoint: string
  notificationEndpoint?: string
  deferredCredentialEndpoint?: string
  credentialTypes?: string[]
  credentialIdentifier?: string // d15: singular
  credentialIdentifiers?: string[] // 1.0 final: array
  credentialConfigurationId?: string
  proof: ProofOfPossession
  token: string
  version: OpenId4VCIVersion
  subjectIssuance?: ExperimentalSubjectIssuance
  issuerState?: string
  authorizationDetails?: (AuthorizationDetailsV1_0_15 | AuthorizationDetailsV1_0)[]
}

export type CreateCredentialRequestOpts = {
  credentialIdentifier?: string
  credentialTypes?: string | string[]
  context?: string[]
  format?: CredentialFormat | OID4VCICredentialFormat
  subjectIssuance?: ExperimentalSubjectIssuance
  version: OpenId4VCIVersion
  credentialConfigurationId?: string
}

export async function buildProof(
  proofInput: ProofOfPossessionBuilder | ProofOfPossession,
  opts: {
    version: OpenId4VCIVersion
    cNonce?: string
  },
) {
  if ('proof_type' in proofInput) {
    if (opts.cNonce) {
      throw Error(`Cnonce param is only supported when using a Proof of possession builder`)
    }
    return await ProofOfPossessionBuilder.fromProof(proofInput as ProofOfPossession, opts.version).build()
  }
  if (opts.cNonce) {
    proofInput.withAccessTokenNonce(opts.cNonce)
  }
  return await proofInput.build()
}

function isOpenIdCredentialDetail(ad: AuthorizationDetailsV1_0_15): ad is AuthorizationDetailsV1_0_15 {
  return typeof ad === 'object' && ad !== null && ad.type === 'openid_credential'
}

function findAuthorizationDetail(
  authorizationDetails: AuthorizationDetailsV1_0_15[] | undefined,
  preferredConfigId?: string,
): AuthorizationDetailsV1_0_15 | undefined {
  if (!authorizationDetails) {
    return undefined
  }

  const openIdCredentialDetails = authorizationDetails.filter(isOpenIdCredentialDetail)

  if (openIdCredentialDetails.length === 0) {
    return undefined
  }

  // If a preferred config ID is specified, try to find a match
  if (preferredConfigId) {
    const match = openIdCredentialDetails.find((detail) => {
      if (typeof detail !== 'object' || detail === null) return false

      const detailObj = detail as any

      if (detailObj.credential_configuration_id === preferredConfigId) {
        return true
      }
      if (detailObj.credential_identifier === preferredConfigId) {
        return true
      }
      return Array.isArray(detailObj.credential_identifiers) && detailObj.credential_identifiers.includes(preferredConfigId)
    })

    if (match) {
      return match
    }
  }

  // Return the first one
  return openIdCredentialDetails[0]
}

export class CredentialRequestClient {
  private readonly _credentialRequestOpts: Partial<CredentialRequestOpts>
  private _isDeferred = false

  get credentialRequestOpts(): CredentialRequestOpts {
    return this._credentialRequestOpts as CredentialRequestOpts
  }

  public isDeferred(): boolean {
    return this._isDeferred
  }

  public getCredentialEndpoint(): string {
    return this.credentialRequestOpts.credentialEndpoint
  }

  public getDeferredCredentialEndpoint(): string | undefined {
    return this.credentialRequestOpts.deferredCredentialEndpoint
  }

  public constructor(builder: CredentialRequestClientBuilderV1_0_15 | CredentialRequestClientBuilderV1_0) {
    this._credentialRequestOpts = { ...builder }
  }

  /**
   * Typically you should not use this method, as it omits a proof from the request.
   * There are certain issuers that in specific circumstances can do without this proof, because they have other means of user binding
   * like using DPoP together with an authorization code flow. These are however rare, so you should be using the acquireCredentialsUsingProof normally
   * @param opts
   */
  public async acquireCredentialsWithoutProof(opts: {
    credentialIdentifier?: string
    credentialTypes?: string | string[]
    context?: string[]
    format: CredentialFormat | OID4VCICredentialFormat
    subjectIssuance?: ExperimentalSubjectIssuance
    createDPoPOpts?: CreateDPoPClientOpts
  }): Promise<OpenIDResponse<CredentialResponse, DPoPResponseParams> & { access_token: string }> {
    const { credentialIdentifier, credentialTypes, format, context, subjectIssuance } = opts

    const request = await this.createCredentialRequestWithoutProof({
      credentialTypes,
      context,
      format,
      version: this.version(),
      credentialIdentifier,
      subjectIssuance,
    })

    if (!supportedOID4VCICredentialFormat.includes(format)) {
      // Check so we can cast format as OID4VCICredentialFormat
      return Promise.reject(Error(`Unsupported credential format: ${format}`))
    }
    return await this.acquireCredentialsUsingRequestWithoutProof(request, format as OID4VCICredentialFormat, opts.createDPoPOpts)
  }

  public async acquireCredentialsUsingProof(opts: {
    proofInput: ProofOfPossessionBuilder | ProofOfPossession
    format: CredentialFormat | OID4VCICredentialFormat
    credentialIdentifier?: string
    credentialTypes?: string | string[]
    context?: string[]
    subjectIssuance?: ExperimentalSubjectIssuance
    createDPoPOpts?: CreateDPoPClientOpts
  }): Promise<OpenIDResponse<CredentialResponse, DPoPResponseParams> & { access_token: string }> {
    const { credentialIdentifier, credentialTypes, proofInput, format, context, subjectIssuance } = opts

    const request = await this.createCredentialRequest({
      proofInput,
      credentialTypes,
      context,
      format,
      version: this.version(),
      credentialIdentifier,
      subjectIssuance,
    })

    // Note: there is no lower version than VER_1_0_15, but code may be useful later
    /*
    if(this.version() <= OpenId4VCIVersion.VER_1_0_15 && !supportedOID4VCICredentialFormat.includes(format)) { // Check so we can cast format as OID4VCICredentialFormat
      return Promise.reject(Error(`Unsupported credential format: ${format}`))
    }
*/

    return await this.acquireCredentialsUsingRequest(request, format as OID4VCICredentialFormat, opts.createDPoPOpts)
  }

  public async acquireCredentialsUsingRequestWithoutProof(
    uniformRequest: CredentialRequest,
    format: OID4VCICredentialFormat,
    createDPoPOpts?: CreateDPoPClientOpts,
  ): Promise<OpenIDResponse<CredentialResponse, DPoPResponseParams> & { access_token: string }> {
    return await this.acquireCredentialsUsingRequestImpl(uniformRequest, format, createDPoPOpts)
  }

  public async acquireCredentialsUsingRequest(
    uniformRequest: CredentialRequest,
    format: OID4VCICredentialFormat,
    createDPoPOpts?: CreateDPoPClientOpts,
  ): Promise<OpenIDResponse<CredentialResponse, DPoPResponseParams> & { access_token: string }> {
    return await this.acquireCredentialsUsingRequestImpl(uniformRequest, format, createDPoPOpts)
  }

  private async acquireCredentialsUsingRequestImpl(
    uniformRequest: CredentialRequest & { proof?: ProofOfPossession },
    format: OID4VCICredentialFormat,
    createDPoPOpts?: CreateDPoPClientOpts,
  ): Promise<OpenIDResponse<CredentialResponse, DPoPResponseParams> & { access_token: string }> {
    // Note: there is no lower version than VER_1_0_15, but code may be useful later
    // if (this.version() < OpenId4VCIVersion.VER_1_0_15) {
    //   throw new Error('Versions below v1.0.15 (draft 15) are not supported by the V15 credential request client.')
    // }
    const credentialEndpoint: string = this.credentialRequestOpts.credentialEndpoint
    if (!isValidURL(credentialEndpoint)) {
      logger.debug(`Invalid credential endpoint: ${credentialEndpoint}`)
      throw new Error(URL_NOT_VALID)
    }
    logger.debug(`Acquiring credential(s) from: ${credentialEndpoint}`)
    logger.debug(`request\n: ${JSON.stringify(uniformRequest, null, 2)}`)
    const requestToken: string = this.credentialRequestOpts.token

    let dPoP = createDPoPOpts ? await createDPoP(getCreateDPoPOptions(createDPoPOpts, credentialEndpoint, { accessToken: requestToken })) : undefined

    let response = (await post(credentialEndpoint, JSON.stringify(uniformRequest), {
      bearerToken: requestToken,
      ...(dPoP && { customHeaders: { dpop: dPoP } }),
    })) as OpenIDResponse<CredentialResponse> & {
      access_token: string
    }

    let nextDPoPNonce = createDPoPOpts?.jwtPayloadProps.nonce
    const retryWithNonce = shouldRetryResourceRequestWithDPoPNonce(response)
    if (retryWithNonce.ok && createDPoPOpts) {
      createDPoPOpts.jwtPayloadProps.nonce = retryWithNonce.dpopNonce
      dPoP = await createDPoP(getCreateDPoPOptions(createDPoPOpts, credentialEndpoint, { accessToken: requestToken }))

      response = (await post(credentialEndpoint, JSON.stringify(uniformRequest), {
        bearerToken: requestToken,
        ...(createDPoPOpts && { customHeaders: { dpop: dPoP } }),
      })) as OpenIDResponse<CredentialResponse> & {
        access_token: string
      }

      const successDPoPNonce = response.origResponse.headers.get('DPoP-Nonce')
      nextDPoPNonce = successDPoPNonce ?? retryWithNonce.dpopNonce
    }

    this._isDeferred = isDeferredCredentialResponse(response)
    if (this.isDeferred() && this.credentialRequestOpts.deferredCredentialAwait && response.successBody) {
      response = await this.acquireDeferredCredential(response.successBody, { bearerToken: this.credentialRequestOpts.token })
    }
    response.access_token = requestToken

    if ((uniformRequest.credential_subject_issuance && response.successBody) || response.successBody?.credential_subject_issuance) {
      if (JSON.stringify(uniformRequest.credential_subject_issuance) !== JSON.stringify(response.successBody?.credential_subject_issuance)) {
        throw Error('Subject signing was requested, but issuer did not provide the options in its response')
      }
    }
    logger.debug(`Credential endpoint ${credentialEndpoint} response:\r\n${JSON.stringify(response, null, 2)}`)

    return {
      ...response,
      ...(nextDPoPNonce && { params: { dpop: { dpopNonce: nextDPoPNonce } } }),
    }
  }

  public async acquireDeferredCredential(
    response: Pick<CredentialResponse, 'transaction_id' | 'acceptance_token' | 'c_nonce'>,
    opts?: {
      bearerToken?: string
    },
  ): Promise<OpenIDResponse<CredentialResponse> & { access_token: string }> {
    const transactionId = response.transaction_id
    const bearerToken = response.acceptance_token ?? opts?.bearerToken
    const deferredCredentialEndpoint = this.getDeferredCredentialEndpoint()
    if (!deferredCredentialEndpoint) {
      throw Error(`No deferred credential endpoint supplied.`)
    } else if (!bearerToken) {
      throw Error(`No bearer token present and refresh for defered endpoint not supported yet`)
      // todo updated bearer token with new c_nonce
    }
    return await acquireDeferredCredential({
      bearerToken,
      transactionId,
      deferredCredentialEndpoint,
      deferredCredentialAwait: this.credentialRequestOpts.deferredCredentialAwait,
      deferredCredentialIntervalInMS: this.credentialRequestOpts.deferredCredentialIntervalInMS,
    })
  }

  public async createCredentialRequestWithoutProof(opts: CreateCredentialRequestOpts): Promise<CredentialRequestV1_0_15 | CredentialRequestV1_0> {
    return await this.createCredentialRequestImpl(opts)
  }

  public async createCredentialRequest(
    opts: CreateCredentialRequestOpts & {
      proofInput: ProofOfPossessionBuilder | ProofOfPossession
    },
  ): Promise<CredentialRequestV1_0_15 | CredentialRequestV1_0> {
    return await this.createCredentialRequestImpl(opts)
  }

  private async createCredentialRequestImpl(
    opts: CreateCredentialRequestOpts & {
      proofInput?: ProofOfPossessionBuilder | ProofOfPossession
    },
  ): Promise<CredentialRequestV1_0_15 | CredentialRequestV1_0> {
    const { proofInput, credentialIdentifier, credentialConfigurationId } = opts
    let proof: ProofOfPossession | undefined = undefined
    if (proofInput) {
      proof = await buildProof(proofInput, opts)
    }

    const issuer_state = this.credentialRequestOpts.issuerState
    const commonBody = {
      ...(issuer_state && { issuer_state }),
      ...(proof && { proof }),
      ...opts.subjectIssuance,
    }

    // 1.0 final: credential_configuration_id is REQUIRED, credential_identifiers is OPTIONAL array
    if (this.version() >= OpenId4VCIVersion.VER_1_0) {
      const authDetail = findAuthorizationDetail(
        this.credentialRequestOpts.authorizationDetails as AuthorizationDetailsV1_0_15[],
        credentialConfigurationId ?? credentialIdentifier,
      )
      const authDetailObj = authDetail && typeof authDetail === 'object' ? (authDetail as any) : null

      const configId =
        credentialConfigurationId ?? authDetailObj?.credential_configuration_id ?? this._credentialRequestOpts.credentialConfigurationId

      if (!configId) {
        return Promise.reject(Error('credential_configuration_id is required for 1.0 final credential request'))
      }

      // Build credential_identifiers array from various sources
      const identifiers: string[] | undefined =
        this._credentialRequestOpts.credentialIdentifiers ??
        (authDetailObj?.credential_identifiers && authDetailObj.credential_identifiers.length > 0
          ? authDetailObj.credential_identifiers
          : credentialIdentifier
            ? [credentialIdentifier]
            : undefined)

      const request: CredentialRequestV1_0 = {
        credential_configuration_id: configId,
        ...(identifiers && identifiers.length > 0 && { credential_identifiers: identifiers }),
        ...commonBody,
      }
      return request
    }

    // Draft 15: credential_identifier (singular) OR credential_configuration_id
    if (this.version() >= OpenId4VCIVersion.VER_1_0_15) {
      const authDetail = findAuthorizationDetail(
        this.credentialRequestOpts.authorizationDetails as AuthorizationDetailsV1_0_15[],
        credentialConfigurationId ?? credentialIdentifier,
      )
      const authDetailObj = authDetail && typeof authDetail === 'object' ? (authDetail as any) : null

      if (authDetailObj?.credential_identifier) {
        return {
          credential_identifier: authDetailObj.credential_identifier,
          ...commonBody,
        }
      }

      if (authDetailObj?.credential_identifiers && authDetailObj.credential_identifiers.length > 0) {
        return {
          credential_identifier: authDetailObj.credential_identifiers[0],
          ...commonBody,
        }
      }

      const configId =
        credentialConfigurationId ?? authDetailObj?.credential_configuration_id ?? this._credentialRequestOpts.credentialConfigurationId
      if (configId) {
        return {
          credential_configuration_id: configId,
          ...commonBody,
        }
      }

      if (credentialIdentifier) {
        return {
          credential_identifier: credentialIdentifier,
          ...commonBody,
        }
      }

      return Promise.reject(Error('No credential_identifier or credential_configuration_id available for v1.0-15 request'))
    }

    throw new Error(`Unsupported version: ${this.version()}`)
  }

  private version(): OpenId4VCIVersion {
    return this.credentialRequestOpts?.version ?? OpenId4VCIVersion.VER_1_0_15
  }
}
