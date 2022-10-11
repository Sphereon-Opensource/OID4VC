import {decodeUriAsJson, encodeJsonAsURI} from "../src/functions/Encoding";
import {AuthzFlowType} from "../src/types/AuthzFlowType";

describe("Issuance Initiation Request", () => {
  it('should parse an object into open-id-URI', () => {
    expect(encodeJsonAsURI({
      issuer: 'https://server.example.com',
      credential_type: 'https://did.example.org/healthCard',
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
    })).toEqual('issuer=https%3A%2F%2Fserver.example.com&credential_type=https%3A%2F%2Fdid.example.org%2FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy')
  })
  it('should parse an array of objects as open-id-URI', () => {
    expect(encodeJsonAsURI([
    {
      issuer: 'https://server.example.com',
      credential_type: 'https://did.example.org/healthCard',
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
    },
    {
      issuer: 'https://server.example1.com',
      credential_type: 'https://did.example1.org/healthCard',
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
    },
    ])).toEqual('issuer=https%3A%2F%2Fserver.example.com&credential_type=https%3A%2F%2Fdid.example.org%2FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy&issuer=https%3A%2F%2Fserver.example1.com&credential_type=https%3A%2F%2Fdid.example1.org%2FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy')
  })
  it('should parse open-id-URI as json object', () => {
    expect(decodeUriAsJson('issuer=https%253A%252F%252Fserver%252Eexample%252Ecom&credential_type=https%253A%252F%252Fdid%252Eexample%252Eorg%252FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy'))
    .toEqual({
      issuer: 'https://server.example.com',
      credential_type: 'https://did.example.org/healthCard',
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
    })
  })
  it('should parse open-id-URI as json array', () => {
    expect(decodeUriAsJson('issuer=https%253A%252F%252Fserver%252Eexample%252Ecom&credential_type=https%253A%252F%252Fdid%252Eexample%252Eorg%252FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy&issuer=https%253A%252F%252Fserver%252Eexample1%252Ecom&credential_type=https%253A%252F%252Fdid%252Eexample1%252Eorg%252FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy'))
    .toEqual([
      {
        issuer: 'https://server.example.com',
        credential_type: 'https://did.example.org/healthCard',
        op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
      },
      {
        issuer: 'https://server.example1.com',
        credential_type: 'https://did.example1.org/healthCard',
        op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
      },
    ])
  })
  it('should return authorization code flow type', () => {
    expect(AuthzFlowType.valueOf({
      issuer: 'test',
      credential_type: 'test'
    })).toEqual(AuthzFlowType.AUTHORIZATION_CODE_FLOW)
  })
  it('should return pre-authorized code flow', () => {
    expect(AuthzFlowType.valueOf({
      issuer: 'test',
      credential_type: 'test',
      pre_authorized_code: 'test'
    })).toEqual(AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW)
  })
})