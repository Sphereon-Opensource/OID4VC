import {AuthzFlowType, convertJsonToURI, convertURIToJsonObject} from "../src"

describe("Issuance Initiation Request", () => {
  it('should parse an object into open-id-URI with a single credential_type', () => {
    expect(convertJsonToURI({
      issuer: 'https://server.example.com',
      credential_type: 'https://did.example.org/healthCard',
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
    }, {
      uriTypeProperties: ['issuer', 'credential_type']
    })).toEqual('issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy')
  })
  it('should parse an object into open-id-URI with an array of credential_type', () => {
    expect(convertJsonToURI({
      issuer: 'https://server.example.com',
      credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
    }, {
      arrayTypeProperties: ['credential_type'],
      uriTypeProperties: ['issuer', 'credential_type']
    })).toEqual('issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy')
  })
  it('should parse an object into open-id-URI with an array of credential_type and json string', () => {
    expect(convertJsonToURI(JSON.stringify({
      issuer: 'https://server.example.com',
      credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
    }), {
      arrayTypeProperties: ['credential_type'],
      uriTypeProperties: ['issuer', 'credential_type']
    })).toEqual('issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy')
  })
  it('should parse open-id-URI as json object with a single credential_type', () => {
    expect(convertURIToJsonObject('issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy', {
      arrayTypeProperties: ['credential_type'],
      requiredProperties: ['issuer', 'credential_type']
    }))
    .toEqual({
      issuer: 'https://server.example.com',
      credential_type: 'https://did.example.org/healthCard',
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
    })
  })
  it('should parse open-id-URI as json object with an array of credential_type', () => {
    expect(convertURIToJsonObject('issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy', {
      arrayTypeProperties: ['credential_type'],
      requiredProperties: ['issuer', 'credential_type']
    }))
    .toEqual({
      issuer: 'https://server.example.com',
      credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
    })
  })
  it('should return authorization code flow type with a single credential_type', () => {
    expect(AuthzFlowType.valueOf({
      issuer: 'test',
      credential_type: 'test'
    })).toEqual(AuthzFlowType.AUTHORIZATION_CODE_FLOW)
  })
  it('should return authorization code flow type with a credential_type array', () => {
    expect(AuthzFlowType.valueOf({
      issuer: 'test',
      credential_type: ['test', 'test1']
    })).toEqual(AuthzFlowType.AUTHORIZATION_CODE_FLOW)
  })
  it('should return pre-authorized code flow with a single credential_type', () => {
    expect(AuthzFlowType.valueOf({
      issuer: 'test',
      credential_type: 'test',
      pre_authorized_code: 'test'
    })).toEqual(AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW)
  })
  it('should return pre-authorized code flow with a credential_type array', () => {
    expect(AuthzFlowType.valueOf({
      issuer: 'test',
      credential_type: ['test', 'test1'],
      pre_authorized_code: 'test'
    })).toEqual(AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW)
  })
})
