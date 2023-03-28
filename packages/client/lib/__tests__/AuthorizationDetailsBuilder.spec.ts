import { AuthorizationDetailsBuilder } from '../AuthorizationDetailsBuilder';

describe('AuthorizationDetailsBuilder test', () => {
  it('should create AuthorizationDetails object from arrays', () => {
    const actual = new AuthorizationDetailsBuilder().withFormats('jwt_vc').withLocations(['test1', 'test2']).withType('openid_credential').build();
    expect(actual).toEqual({
      type: 'openid_credential',
      format: 'jwt_vc',
      locations: ['test1', 'test2'],
    });
  });
  it('should create AuthorizationDetails object from single objects', () => {
    const actual = new AuthorizationDetailsBuilder().withFormats('jwt_vc').withLocations(['test1']).withType('openid_credential').build();
    expect(actual).toEqual({
      type: 'openid_credential',
      format: 'jwt_vc',
      locations: ['test1'],
    });
  });
  it('should create AuthorizationDetails object if locations is missing', () => {
    const actual = new AuthorizationDetailsBuilder().withFormats('jwt_vc').withType('openid_credential').build();
    expect(actual).toEqual({
      type: 'openid_credential',
      format: 'jwt_vc',
    });
  });
  it('should fail if type is missing', () => {
    expect(() => {
      new AuthorizationDetailsBuilder().withFormats('jwt_vc').withLocations(['test1']).build();
    }).toThrow(Error('Type and format are required properties'));
  });
  it('should fail if format is missing', () => {
    expect(() => {
      new AuthorizationDetailsBuilder().withType('openid_credential').withLocations(['test1']).build();
    }).toThrow(Error('Type and format are required properties'));
  });
  it('should be able to add random field to the object', () => {
    const actual = new AuthorizationDetailsBuilder().withFormats('jwt_vc').withType('openid_credential').build();
    actual['random'] = 'test';
    expect(actual).toEqual({
      type: 'openid_credential',
      format: 'jwt_vc',
      random: 'test',
    });
  });
});
