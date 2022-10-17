import { AuthzFlowType, convertJsonToURI, convertURIToJsonObject } from '../lib';
import { IssuanceInitiation } from '../lib';

describe('JSON To URI', () => {
  it('should parse an object into open-id-URI with a single credential_type', () => {
    expect(
      convertJsonToURI(
        {
          issuer: 'https://server.example.com',
          credential_type: 'https://did.example.org/healthCard',
          op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
        },
        {
          uriTypeProperties: ['issuer', 'credential_type'],
        }
      )
    ).toEqual(
      'issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy'
    );
  });
  it('should parse an object into open-id-URI with an array of credential_type', () => {
    expect(
      convertJsonToURI(
        {
          issuer: 'https://server.example.com',
          credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
          op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
        },
        {
          arrayTypeProperties: ['credential_type'],
          uriTypeProperties: ['issuer', 'credential_type'],
        }
      )
    ).toEqual(
      'issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy'
    );
  });
  it('should parse an object into open-id-URI with an array of credential_type and json string', () => {
    expect(
      convertJsonToURI(
        JSON.stringify({
          issuer: 'https://server.example.com',
          credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
          op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
        }),
        {
          arrayTypeProperties: ['credential_type'],
          uriTypeProperties: ['issuer', 'credential_type'],
        }
      )
    ).toEqual(
      'issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy'
    );
  });
});
describe('URI To Json Object', () => {
  it('should parse open-id-URI as json object with a single credential_type', () => {
    expect(
      convertURIToJsonObject(
        'issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy',
        {
          arrayTypeProperties: ['credential_type'],
          requiredProperties: ['issuer', 'credential_type'],
        }
      )
    ).toEqual({
      issuer: 'https://server.example.com',
      credential_type: 'https://did.example.org/healthCard',
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
    });
  });
  it('should parse open-id-URI as json object with an array of credential_type', () => {
    expect(
      convertURIToJsonObject(
        'issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy',
        {
          arrayTypeProperties: ['credential_type'],
          requiredProperties: ['issuer', 'credential_type'],
        }
      )
    ).toEqual({
      issuer: 'https://server.example.com',
      credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
    });
  });
});

describe('Authorization Request', () => {
  it('Should return Issuance Initiation Request with base URL from URI', () => {
    expect(
      IssuanceInitiation.fromURI(
        'https://server.example.com?issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy'
      )
    ).toEqual({
      baseUrl: 'https://server.example.com',
      issuanceInitiationRequest: {
        credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
        issuer: 'https://server.example.com',
        op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
      },
    });
  });
});

describe('Authorization Flow Type determination', () => {
  it('should return authorization code flow type with a single credential_type', () => {
    expect(
      AuthzFlowType.valueOf({
        issuer: 'test',
        credential_type: 'test',
      })
    ).toEqual(AuthzFlowType.AUTHORIZATION_CODE_FLOW);
  });
  it('should return authorization code flow type with a credential_type array', () => {
    expect(
      AuthzFlowType.valueOf({
        issuer: 'test',
        credential_type: ['test', 'test1'],
      })
    ).toEqual(AuthzFlowType.AUTHORIZATION_CODE_FLOW);
  });
  it('should return pre-authorized code flow with a single credential_type', () => {
    expect(
      AuthzFlowType.valueOf({
        issuer: 'test',
        credential_type: 'test',
        pre_authorized_code: 'test',
      })
    ).toEqual(AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW);
  });
  it('should return pre-authorized code flow with a credential_type array', () => {
    expect(
      AuthzFlowType.valueOf({
        issuer: 'test',
        credential_type: ['test', 'test1'],
        pre_authorized_code: 'test',
      })
    ).toEqual(AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW);
  });
});
