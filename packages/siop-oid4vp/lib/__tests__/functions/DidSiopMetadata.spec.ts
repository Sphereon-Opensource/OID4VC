import { SigningAlgo } from '@sphereon/oid4vc-common'
import { Format, IProofType } from '@sphereon/ssi-types'
import { describe, expect, it } from 'vitest'
import { SIOPErrors, supportedCredentialsFormats } from '../..'

describe('DidSiopMetadata should ', () => {
  it('find supportedCredentialsFormats correctly', async function () {
    const rpFormat: Format = {
      ldp_vc: {
        proof_type_values: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
      },
      jwt_vc: {
        alg_values: [SigningAlgo.ES256, SigningAlgo.ES256K],
      },
    }
    const opFormat: Format = {
      jwt_vc: {
        alg_values: [SigningAlgo.ES256, SigningAlgo.ES256K],
      },
    }
    expect(supportedCredentialsFormats(rpFormat, opFormat)).toStrictEqual({ jwt_vc: { alg: ['ES256', 'ES256K'] } })
  })

  it('throw CREDENTIAL_FORMATS_NOT_SUPPORTED for algs not matching', async function () {
    const rpFormat: Format = {
      ldp_vc: {
        proof_type_values: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
      },
      jwt_vc: {
        alg_values: [SigningAlgo.ES256K],
      },
    }
    const opFormat: Format = {
      jwt_vc: {
        alg_values: [SigningAlgo.ES256],
      },
    }
    expect(() => supportedCredentialsFormats(rpFormat, opFormat)).toThrow(SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED)
  })

  it('throw CREDENTIAL_FORMATS_NOT_SUPPORTED for types not matching', async function () {
    const rpFormat: Format = {
      ldp_vc: {
        proof_type_values: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
      },
    }
    const opFormat: Format = {
      jwt_vc: {
        alg_values: [SigningAlgo.ES256],
      },
    }
    expect(() => supportedCredentialsFormats(rpFormat, opFormat)).toThrow(SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED)
  })

  it('throw CREDENTIALS_FORMATS_NOT_PROVIDED', async function () {
    const rpFormat: Format = {}
    const opFormat: Format = {
      jwt_vc: {
        alg_values: [SigningAlgo.ES256, SigningAlgo.ES256K],
      },
    }
    expect(() => supportedCredentialsFormats(rpFormat, opFormat)).toThrow(SIOPErrors.CREDENTIALS_FORMATS_NOT_PROVIDED)
  })
})
