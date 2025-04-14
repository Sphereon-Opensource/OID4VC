import * as v from 'valibot'

import {
  vJarmClientMetadata,
  vJarmClientMetadataEncrypt,
  vJarmClientMetadataSign,
  vJarmClientMetadataSignEncrypt,
} from '../metadata/v-jarm-client-metadata.js'
import { vJarmServerMetadata } from '../metadata/v-jarm-server-metadata.js'
import { assertValueSupported } from '../utils.js'

export const vJarmAuthResponseValidateMetadataInput = v.object({
  client_metadata: vJarmClientMetadata,
  server_metadata: v.partial(vJarmServerMetadata),
})
export type JarmMetadataValidate = v.InferInput<typeof vJarmAuthResponseValidateMetadataInput>

export const vJarmMetadataValidateOut = v.variant('type', [
  v.object({
    type: v.literal('signed'),
    client_metadata: vJarmClientMetadataSign,
  }),
  v.object({
    type: v.literal('encrypted'),
    client_metadata: vJarmClientMetadataEncrypt,
  }),
  v.object({
    type: v.literal('signed encrypted'),
    client_metadata: vJarmClientMetadataSignEncrypt,
  }),
])

export const jarmMetadataValidate = (vJarmMetadataValidate: JarmMetadataValidate): v.InferOutput<typeof vJarmMetadataValidateOut> => {
  const { client_metadata, server_metadata } = vJarmMetadataValidate
  const { authorization_encrypted_response_alg, authorization_encrypted_response_enc, authorization_signed_response_alg } = client_metadata

  assertValueSupported({
    supported: server_metadata.authorization_signing_alg_values_supported ?? [],
    actual: authorization_signed_response_alg,
    required: !!authorization_signed_response_alg,
    error: new Error('Invalid authorization_signed_response_alg'),
  })

  assertValueSupported({
    supported: server_metadata.authorization_encryption_alg_values_supported ?? [],
    actual: authorization_encrypted_response_alg,
    required: !!authorization_encrypted_response_alg,
    error: new Error('Invalid authorization_encrypted_response_alg'),
  })

  assertValueSupported({
    supported: server_metadata.authorization_encryption_enc_values_supported ?? [],
    actual: authorization_encrypted_response_enc,
    required: !!authorization_encrypted_response_enc,
    error: new Error('Invalid authorization_encrypted_response_enc'),
  })

  if (authorization_signed_response_alg && authorization_encrypted_response_alg && authorization_encrypted_response_enc) {
    return {
      type: 'signed encrypted',
      client_metadata: {
        authorization_signed_response_alg,
        authorization_encrypted_response_alg,
        authorization_encrypted_response_enc,
      },
    }
  } else if (authorization_signed_response_alg && !authorization_encrypted_response_alg && !authorization_encrypted_response_enc) {
    return {
      type: 'signed',
      client_metadata: { authorization_signed_response_alg },
    }
  } else if (!authorization_signed_response_alg && authorization_encrypted_response_alg && authorization_encrypted_response_enc) {
    return {
      type: 'encrypted',
      client_metadata: { authorization_encrypted_response_alg, authorization_encrypted_response_enc },
    }
  } else {
    throw new Error(`Invalid jarm client_metadata combination`)
  }
}
