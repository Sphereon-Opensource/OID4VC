import {decodeURIAsJson, encodeJsonAsURI} from "../src/functions/Encoding";
import {AuthzFlowType} from "../src/types/AuthzFlowType";

describe("Issuance Initiation Request", () => {
  it('should parse an object into open-id-URI', () => {
    expect(encodeJsonAsURI({
      issuer: 'https://server.example.com',
      credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
    }, {
      arrayTypeProperties: ['credential_type'],
      urlTypeProperties: ['issuer', 'credential_type']
    })).toEqual('issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy')
  })

  it('should parse open-id-URI as json object', () => {
    expect(decodeURIAsJson('issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy', {
      duplicatedProperties: ['credential_type'],
      requiredProperties: ['issuer', 'credential_type']
    }))
    .toEqual({
      issuer: 'https://server.example.com',
      credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
    })
  })
  it('should return authorization code flow type', () => {
    expect(AuthzFlowType.valueOf({
      issuer: 'test',
      credential_type: ['test']
    })).toEqual(AuthzFlowType.AUTHORIZATION_CODE_FLOW)
  })
  it('should return pre-authorized code flow', () => {
    expect(AuthzFlowType.valueOf({
      issuer: 'test',
      credential_type: ['test'],
      pre_authorized_code: 'test'
    })).toEqual(AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW)
  })
})