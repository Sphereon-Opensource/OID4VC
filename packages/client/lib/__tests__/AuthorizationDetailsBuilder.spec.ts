import { OID4VCICredentialFormat } from '@sphereon/oid4vci-common'
import { describe, expect, it } from 'vitest'

import { AuthorizationDetailsBuilder } from '../AuthorizationDetailsBuilder'

describe('AuthorizationDetailsBuilder test', () => {
  it('should create AuthorizationDetails object from arrays', () => {
    const actual = new AuthorizationDetailsBuilder()
      .withFormats('jwt_vc' as OID4VCICredentialFormat)
      .withLocations(['test1', 'test2'])
      .buildJwtVcJson()
    expect(actual).toEqual({
      type: 'openid_credential',
      format: 'jwt_vc',
      locations: ['test1', 'test2'],
    })
  })
  it('should create AuthorizationDetails object from single objects', () => {
    const actual = new AuthorizationDetailsBuilder()
      .withFormats('jwt_vc' as OID4VCICredentialFormat)
      .withLocations(['test1'])
      .buildJwtVcJson()
    expect(actual).toEqual({
      type: 'openid_credential',
      format: 'jwt_vc',
      locations: ['test1'],
    })
  })
  it('should create AuthorizationDetails object if locations is missing', () => {
    const actual = new AuthorizationDetailsBuilder().withFormats('jwt_vc' as OID4VCICredentialFormat).buildJwtVcJson()
    expect(actual).toEqual({
      type: 'openid_credential',
      format: 'jwt_vc',
    })
  })

  it('should fail if format is missing', () => {
    expect(() => {
      new AuthorizationDetailsBuilder().withLocations(['test1']).buildJwtVcJson()
    }).toThrow(Error('Type and format are required properties'))
  })
})
