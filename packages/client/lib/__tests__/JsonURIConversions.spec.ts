import { convertJsonToURI, convertURIToJsonObject, JsonURIMode, OpenId4VCIVersion } from '@sphereon/oid4vci-common'
import { describe, expect, it } from 'vitest'

describe('JSON To URI v15', () => {
  it('should parse a credential offer object into URI with credential_configuration_ids', () => {
    expect(
      convertJsonToURI(
        {
          credential_issuer: 'https://server.example.com',
          credential_configuration_ids: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
          grants: {
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
              'pre-authorized_code': 'eyJhbGciOiJSU0Et...FYUaBy'
            }
          }
        },
        {
          version: OpenId4VCIVersion.VER_1_0_15,
          mode: JsonURIMode.JSON_STRINGIFY
        },
      ),
    ).toEqual(
      '%7B%22credential_issuer%22%3A%22https%3A%2F%2Fserver.example.com%22%2C%22credential_configuration_ids%22%3A%5B%22https%3A%2F%2Fdid.example.org%2FhealthCard%22%2C%22https%3A%2F%2Fdid.example.org%2FdriverLicense%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22eyJhbGciOiJSU0Et...FYUaBy%22%7D%7D%7D'
    )
  })
})


describe('URI To Json Object', () => {
  it('should parse open-id-URI as json object with a single credential_type', () => {
    expect(
      convertURIToJsonObject(
        'issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy',
        {
          arrayTypeProperties: ['credential_type'],
          requiredProperties: ['issuer', 'credential_type'],
        },
      ),
    ).toEqual({
      issuer: 'https://server.example.com',
      credential_type: ['https://did.example.org/healthCard'],
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
    })
  })
  it('should parse open-id-URI as json object with an array of credential_type', () => {
    expect(
      convertURIToJsonObject(
        'issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy',
        {
          arrayTypeProperties: ['credential_type'],
          requiredProperties: ['issuer', 'credential_type'],
        },
      ),
    ).toEqual({
      issuer: 'https://server.example.com',
      credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
    })
  })
})
