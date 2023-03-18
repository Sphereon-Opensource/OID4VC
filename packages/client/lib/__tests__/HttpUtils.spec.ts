import { isValidURL } from '../functions';

describe('httputils.isValidURL', () => {
  it('Should return true for http://localhost', () => {
    expect(isValidURL('http://localhost:4000/some/random/path')).toBeTruthy();
  });
  it('Should return false when no scheme is used', () => {
    expect(isValidURL('sphereon.com/some/random/path')).toBeFalsy();
  });
  it('Should return false when a different scheme than http(s) is used', () => {
    expect(isValidURL('ftp://sphereon.com/some/random/path')).toBeFalsy();
  });
  it('Should return false for invalid scheme http:xxx', () => {
    expect(isValidURL('http:localhost:4000/some/random/path')).toBeFalsy();
  });
  it('Should return false for non-localhost hostname with no domain', () => {
    expect(isValidURL('https://mydomain/some/random/path')).toBeFalsy();
  });
  it('Should return true for https://sphereon.com', () => {
    expect(isValidURL('https://sphereon.com/some/random/path')).toBeTruthy();
  });
  it('Should return true for https://sphereon.com:400', () => {
    expect(isValidURL('https://sphereon.com:400/some/random/path')).toBeTruthy();
  });
  it('Should return true when no path is supplied', () => {
    expect(isValidURL('https://sphereon.com')).toBeTruthy();
  });
  it('Should return true for https://sphereon.com:400/some/random/path?query=param', () => {
    expect(isValidURL('https://sphereon.com:400/some/random/path?query=param')).toBeTruthy();
  });
  it('Should return true for https://sphereon.com:400/some/random/path#fragment', () => {
    expect(isValidURL('https://sphereon.com:400/some/random/path#fragment')).toBeTruthy();
  });
  it('Should return true for https://sphereon.com:400/some/random/path?query=param#fragment', () => {
    expect(isValidURL('https://sphereon.com:400/some/random/path?query=param#fragment')).toBeTruthy();
  });
});
