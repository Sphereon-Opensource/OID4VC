import { convertJsonToURI, convertURIToJsonObject, OpenId4VCIVersion } from '@sphereon/oid4vci-common';

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
          version: OpenId4VCIVersion.VER_1_0_09,
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
          version: OpenId4VCIVersion.VER_1_0_09,
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
          version: OpenId4VCIVersion.VER_1_0_09,
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
