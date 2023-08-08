import { convertJsonToURI, convertURIToJsonObject, OpenId4VCIVersion } from '@sphereon/oid4vci-common';

describe('JSON To URI v8', () => {
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
          version: OpenId4VCIVersion.VER_1_0_08,
        },
      ),
    ).toEqual(
      'issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy',
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
          version: OpenId4VCIVersion.VER_1_0_08,
        },
      ),
    ).toEqual(
      'issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy',
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
          version: OpenId4VCIVersion.VER_1_0_08,
        },
      ),
    ).toEqual(
      'issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy',
    );
  });
});

describe('JSON To URI v9', () => {
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
        },
      ),
    ).toEqual(
      '%7B%22issuer%22%3A%22https%3A%2F%2Fserver.example.com%22%2C%22credential_type%22%3A%22https%3A%2F%2Fdid.example.org%2FhealthCard%22%2C%22op_state%22%3A%22eyJhbGciOiJSU0Et...FYUaBy%22%7D',
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
        },
      ),
    ).toEqual(
      '%7B%22issuer%22%3A%22https%3A%2F%2Fserver.example.com%22%2C%22credential_type%22%3A%5B%22https%3A%2F%2Fdid.example.org%2FhealthCard%22%2C%22https%3A%2F%2Fdid.example.org%2FdriverLicense%22%5D%2C%22op_state%22%3A%22eyJhbGciOiJSU0Et...FYUaBy%22%7D',
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
        },
      ),
    ).toEqual(
      '%7B%22issuer%22%3A%22https%3A%2F%2Fserver.example.com%22%2C%22credential_type%22%3A%5B%22https%3A%2F%2Fdid.example.org%2FhealthCard%22%2C%22https%3A%2F%2Fdid.example.org%2FdriverLicense%22%5D%2C%22op_state%22%3A%22eyJhbGciOiJSU0Et...FYUaBy%22%7D',
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
        },
      ),
    ).toEqual({
      issuer: 'https://server.example.com',
      credential_type: ['https://did.example.org/healthCard'],
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
        },
      ),
    ).toEqual({
      issuer: 'https://server.example.com',
      credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
    });
  });
});
