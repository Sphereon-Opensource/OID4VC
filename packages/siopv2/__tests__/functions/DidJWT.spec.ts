import { JWTDecoded } from 'did-jwt/lib/JWT';

import {
  getIssuerDidFromJWT,
  getMethodFromDid,
  getNetworkFromDid,
  getSubDidFromPayload,
  isEd25519DidKeyMethod,
  isIssSelfIssued,
  parseJWT,
  SIOPErrors,
  toSIOPRegistrationDidMethod,
} from '../../src';

const validJWT =
  'eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXRocjoweDk3NTgzNmREM0Y1RTk4QzE5RjBmM2I4N0Y5OWFGMzA1MDAyNkREQzIjY29udHJvbGxlciIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MzIyNzE4MDMuMjEyLCJleHAiOjE2MzIyNzI0MDMuMjEyLCJpc3MiOiJodHRwczovL3NlbGYtaXNzdWVkLm1lL3YyIiwic3ViIjoiZGlkOmV0aHI6MHg5NzU4MzZkRDNGNUU5OEMxOUYwZjNiODdGOTlhRjMwNTAwMjZEREMyIiwiYXVkIjoiaHR0cHM6Ly9hY21lLmNvbS9oZWxsbyIsImRpZCI6ImRpZDpldGhyOjB4OTc1ODM2ZEQzRjVFOThDMTlGMGYzYjg3Rjk5YUYzMDUwMDI2RERDMiIsInN1Yl90eXBlIjoiZGlkIiwic3ViX2p3ayI6eyJraWQiOiJkaWQ6ZXRocjoweDk3NTgzNmREM0Y1RTk4QzE5RjBmM2I4N0Y5OWFGMzA1MDAyNkREQzIjY29udHJvbGxlciIsImt0eSI6IkVDIiwiY3J2Ijoic2VjcDI1NmsxIiwieCI6IkloUXVEek5BY1dvczVXeDd4U1NHMks2Zkp6MnBobU1nbUZ4UE1xaEU4XzgiLCJ5IjoiOTlreGpCMVgzaUtkRXZkbVFDbllqVm5PWEJyc2VwRGdlMFJrek1aUDN1TSJ9LCJzdGF0ZSI6ImQ2NzkzYjQ2YWIyMzdkMzczYWRkNzQwMCIsIm5vbmNlIjoiU1JXSzltSVpFd1F6S3dsZlZoMkE5SV9weUtBT0tnNDAtWDJqbk5aZEN0byIsInJlZ2lzdHJhdGlvbiI6eyJpc3N1ZXIiOiJodHRwczovL3NlbGYtaXNzdWVkLm1lL3YyIiwicmVzcG9uc2VfdHlwZXNfc3VwcG9ydGVkIjoiaWRfdG9rZW4iLCJhdXRob3JpemF0aW9uX2VuZHBvaW50Ijoib3BlbmlkOiIsInNjb3Blc19zdXBwb3J0ZWQiOiJvcGVuaWQiLCJpZF90b2tlbl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVTMjU2SyIsIkVkRFNBIl0sInJlcXVlc3Rfb2JqZWN0X3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTZLIiwiRWREU0EiXSwic3ViamVjdF90eXBlc19zdXBwb3J0ZWQiOiJwYWlyd2lzZSJ9fQ.coLQr2hQuMwEfYUd3HdFt-ixhsaicc37cC9cwmQ2U5hfxRhAb871s9G1GAo3qhsa9v3t0G1bTX2J9WhLaC5J_Q';

describe('DidJWT ', () => {
  it('getIssuerDidFromPayload: should pass if issuer is correct', async function () {
    const decoded: JWTDecoded = parseJWT(validJWT);
    const result = getSubDidFromPayload(decoded.payload);
    expect(result).toBeDefined();
  });

  it('isIssSelfIssued: should pass if fails', async function () {
    const decoded = parseJWT(validJWT);
    decoded.payload.iss = 'https://3rd-party-issued.me/v2';
    const result = isIssSelfIssued(decoded.payload);
    expect(result).toBe(false);
  });

  it('isIssSelfIssued: should pass if isIssSelfIssued', async function () {
    const decoded = parseJWT(validJWT);
    const result = isIssSelfIssued(decoded.payload);
    expect(result).toBe(true);
  });

  it('getIssuerDidFromJWT: should pass if returns correct result', async function () {
    const result = getIssuerDidFromJWT(validJWT);
    expect(result).toBe('did:ethr:0x975836dD3F5E98C19F0f3b87F99aF3050026DDC2');
  });

  it('getIssuerDidFromJWT: should pass if throws NO_ISS_DID', async function () {
    let err = undefined;
    try {
      getIssuerDidFromJWT(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
      );
    } catch (e) {
      err = e;
    }
    expect(err?.message).toContain(SIOPErrors.NO_ISS_DID);
  });

  it('parseJWT: should pass if method throws Incorrect format JWT', async function () {
    let err = undefined;
    try {
      parseJWT('eysfsdfsdfsd');
    } catch (e) {
      err = e;
    }
    expect(err?.message).toContain('Incorrect format JWT');
  });

  it('parseJWT: should pass if method returns with correct decoded ', async function () {
    const result = parseJWT(
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    );
    expect(result.payload.name).toBe('John Doe');
  });

  it('getMethodFromDid: should pass if throws BAD_PARAMS on calling with null', async function () {
    let err = undefined;
    try {
      getMethodFromDid(null);
    } catch (e) {
      err = e;
    }
    expect(err?.message).toBe(SIOPErrors.BAD_PARAMS);
  });

  it('getMethodFromDid: should pass if throws BAD_PARAMS on calling with less than 3 segments', async function () {
    let err = undefined;
    try {
      getMethodFromDid('pid:123');
    } catch (e) {
      err = e;
    }
    expect(err?.message).toBe(SIOPErrors.BAD_PARAMS);
  });

  it('getMethodFromDid: should pass if idx #1 is returned', async function () {
    const result = getMethodFromDid('did:ethr:0x226e2e2223333c2e4c65652e452d412d50611111');
    expect(result).toBe('ethr');
  });

  it('getNetworkFromDid: should pass if throws BAD_PARAMS', async function () {
    try {
      getNetworkFromDid('pid:ethr:0x226e2e2223333c2e4c65652e452d412d50611111');
    } catch (e) {
      expect(e.message).toBe(SIOPErrors.BAD_PARAMS);
    }
  });

  it('getNetworkFromDid: should pass if idx #2 is returned', async function () {
    const result = getNetworkFromDid('did:ethr:method:0x226e2e2223333c2e4c65652e452d412d50611111');
    expect(result).toBe('method');
  });

  it('getNetworkFromDid: should pass if idx #2 and #3 is returned', async function () {
    const result = getNetworkFromDid('did:ethr:method1:method2:0x226e2e2223333c2e4c65652e452d412d50611111');
    expect(result).toBe('method1:method2');
  });

  it('getNetworkFromDid: should pass if network is mainnet', async function () {
    const result = getNetworkFromDid('did:ethr:0x226e2e2223333c2e4c65652e452d412d50611111');
    expect(result).toBe('mainnet');
  });

  it('toSIOPRegistrationDidMethod: should pass if fails', async function () {
    const result = toSIOPRegistrationDidMethod('pid:ethr:0x226e2e2223333c2e4c65652e452d412d50611111');
    expect(result).toBe('did:pid');
  });

  it('toSIOPRegistrationDidMethod: should pass if', async function () {
    const result = toSIOPRegistrationDidMethod('did:ethr:0x226e2e2223333c2e4c65652e452d412d50611111');
    expect(result).toBe('did:ethr');
  });

  it('is ED25519 Did key', async function () {
    const result = isEd25519DidKeyMethod('did:key:z6MkwVRpJ1AHXrb3z1Ao59a87MB6NqvUiseQ9XnVDf7RFE3K');
    expect(result).toBe(true);
  });
});
