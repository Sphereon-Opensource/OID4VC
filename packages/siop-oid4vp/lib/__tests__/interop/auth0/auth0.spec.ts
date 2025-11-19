import { describe, expect, it } from 'vitest'
import { DcqlQuery, DcqlQueryResult, DcqlW3cVcCredential } from 'dcql'
import { CredentialMapper } from '@sphereon/ssi-types'
import { parsedDcqlQueryAny, VCs } from './fixtures'
import { Json } from '../../../types'

describe.skip('auth0 presentation tool', () => {
  it('any match query should return all credentials', async () => {
    expect(VCs).toHaveLength(5)
    const dcqlCredentials = VCs.map((vc) => {
      if (typeof vc === 'string') {
        return {
          credential_format: 'jwt_vc_json',
          claims: CredentialMapper.decodeVerifiableCredential(vc).decodedPayload as { [x: string]: Json },
          type: CredentialMapper.decodeVerifiableCredential(vc).decodedPayload.vct,
          cryptographic_holder_binding: true,
        } satisfies DcqlW3cVcCredential
      } else {
        return {
          credential_format: 'ldp_vc',
          claims: vc.credentialSubject as { [x: string]: Json },
          type: vc.type,
          cryptographic_holder_binding: true,
        } satisfies DcqlW3cVcCredential
      }
    })

    const dcqlQueryResult: DcqlQueryResult = DcqlQuery.query(parsedDcqlQueryAny, dcqlCredentials)
    expect(dcqlQueryResult.credential_matches).toHaveLength(5)
  })
})
