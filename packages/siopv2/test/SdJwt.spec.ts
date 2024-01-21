import { createHash } from 'node:crypto';

import { IPresentationDefinition, SdJwtDecodedVerifiableCredentialWithKbJwtInput } from '@sphereon/pex';
import { OriginalVerifiableCredential } from '@sphereon/ssi-types';
import { IVerifyCallbackArgs, IVerifyCredentialResult } from '@sphereon/wellknown-dids-client';

import {
  OP,
  PassBy,
  PresentationDefinitionWithLocation,
  PresentationExchange,
  PresentationSignCallback,
  PresentationVerificationCallback,
  PropertyTarget,
  ResponseIss,
  ResponseType,
  RevocationVerification,
  RP,
  Scope,
  SigningAlgo,
  SubjectType,
  SupportedVersion,
  VPTokenLocation,
} from '../src';

import { WELL_KNOWN_OPENID_FEDERATION } from './TestUtils';
import {
  VERIFIER_LOGO_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT_NL,
  VERIFIERZ_PURPOSE_TO_VERIFY,
  VERIFIERZ_PURPOSE_TO_VERIFY_NL,
} from './data/mockedData';

const hasher = (data: string) => createHash('sha256').update(data).digest();
jest.setTimeout(30000);

const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello';

const HOLDER_DID = 'did:example:ebfeb1f712ebc6f1c276e12ec21';
const SD_JWT_VC =
  'eyJhbGciOiJFZERTQSIsInR5cCI6InZjK3NkLWp3dCJ9.eyJpYXQiOjE3MDA0NjQ3MzYwNzYsImlzcyI6ImRpZDprZXk6c29tZS1yYW5kb20tZGlkLWtleSIsIm5iZiI6MTcwMDQ2NDczNjE3NiwidmN0IjoiaHR0cHM6Ly9oaWdoLWFzc3VyYW5jZS5jb20vU3RhdGVCdXNpbmVzc0xpY2Vuc2UiLCJ1c2VyIjp7Il9zZCI6WyI5QmhOVDVsSG5QVmpqQUp3TnR0NDIzM216MFVVMUd3RmFmLWVNWkFQV0JNIiwiSVl5d1FQZl8tNE9hY2Z2S2l1cjRlSnFMa1ZleWRxcnQ1Y2UwMGJReWNNZyIsIlNoZWM2TUNLakIxeHlCVl91QUtvLURlS3ZvQllYbUdBd2VGTWFsd05xbUEiLCJXTXpiR3BZYmhZMkdoNU9pWTRHc2hRU1dQREtSeGVPZndaNEhaQW5YS1RZIiwiajZ6ZFg1OUJYZHlTNFFaTGJITWJ0MzJpenRzWXdkZzRjNkpzWUxNc3ZaMCIsInhKR3Radm41cFM4VEhqVFlJZ3MwS1N5VC1uR3BSR3hDVnp6c1ZEbmMyWkUiXX0sImxpY2Vuc2UiOnsibnVtYmVyIjoxMH0sImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwieSI6Ilp4amlXV2JaTVFHSFZXS1ZRNGhiU0lpcnNWZnVlY0NFNnQ0alQ5RjJIWlEifX0sIl9zZF9hbGciOiJzaGEtMjU2IiwiX3NkIjpbIl90YnpMeHBaeDBQVHVzV2hPOHRUZlVYU2ZzQjVlLUtrbzl3dmZaaFJrYVkiLCJ1WmNQaHdUTmN4LXpNQU1zemlYMkFfOXlJTGpQSEhobDhEd2pvVXJLVVdZIl19.HAcudVInhNpXkTPQGNosjKTFRJWgKj90NpfloRaDQchGd4zxc1ChWTCCPXzUXTBypASKrzgjZCiXlTr0bzmLAg~WyJHeDZHRUZvR2t6WUpWLVNRMWlDREdBIiwiZGF0ZU9mQmlydGgiLCIyMDAwMDEwMSJd~WyJ1LUt3cmJvMkZfTExQekdSZE1XLUtBIiwibmFtZSIsIkpvaG4iXQ~WyJNV1ZieGJqVFZxUXdLS3h2UGVZdWlnIiwibGFzdE5hbWUiLCJEb2UiXQ~';

const presentationSignCallback: PresentationSignCallback = async (_args) => {
  const kbJwt = (_args.presentation as SdJwtDecodedVerifiableCredentialWithKbJwtInput).kbJwt;

  // In real life scenario, the KB-JWT must be signed
  // As the KB-JWT is a normal JWT, the user does not need an sd-jwt implementation in the presentation sign callback
  // NOTE: should the presentation just be the KB-JWT header + payload instead of the whole decoded SD JWT?
  expect(kbJwt).toEqual({
    header: {
      typ: 'kb+jwt',
    },
    payload: {
      _sd_hash: expect.any(String),
      iat: expect.any(Number),
      nonce: undefined,
    },
  });

  return SD_JWT_VC;
};

function getPresentationDefinition(): IPresentationDefinition {
  return {
    id: '32f54163-7166-48f1-93d8-ff217bdb0653',
    name: 'Conference Entry Requirements',
    purpose: 'We can only allow people associated with Washington State business representatives into conference areas',
    format: {
      'vc+sd-jwt': {},
    },
    input_descriptors: [
      {
        id: 'wa_driver_license',
        name: 'Washington State Business License',
        purpose: 'We can only allow licensed Washington State business representatives into the WA Business Conference',
        constraints: {
          limit_disclosure: 'required',
          fields: [
            {
              path: ['$.vct'],
              filter: {
                type: 'string',
                const: 'https://high-assurance.com/StateBusinessLicense',
              },
            },
            {
              path: ['$.license.number'],
              filter: {
                type: 'number',
              },
            },
            {
              path: ['$.user.name'],
              filter: {
                type: 'string',
              },
            },
          ],
        },
      },
    ],
  };
}

function getVCs(): OriginalVerifiableCredential[] {
  return [SD_JWT_VC];
}

describe('RP and OP interaction should', () => {
  it('succeed when calling with presentation definitions and right verifiable presentation', async () => {
    const rpMockEntity = {
      hexPrivateKey: '2bbd6a78be9ab2193bcf74aa6d39ab59c1d1e2f7e9ef899a38fb4d94d8aa90e2',
      did: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024',
      didKey: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024#controllerKey',
    };

    const opMockEntity = {
      hexPrivateKey: '73d24dd0fb69abdc12e7a99d8f9a970fdc8ad90598cc64cff35b584220ace0c8',
      did: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca',
      didKey: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca#controllerKey',
    };

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const verifyCallback = async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true });

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const presentationVerificationCallback: PresentationVerificationCallback = async (_args) => {
      return { verified: true };
    };

    const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
      .withClientId(rpMockEntity.did)
      .withScope('test')
      .withHasher(hasher)
      .withResponseType([ResponseType.ID_TOKEN, ResponseType.VP_TOKEN])
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withPresentationDefinition({ definition: getPresentationDefinition() }, [PropertyTarget.REQUEST_OBJECT, PropertyTarget.AUTHORIZATION_REQUEST])
      .withPresentationVerification(presentationVerificationCallback)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withRequestBy(PassBy.VALUE)
      .withInternalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey, SigningAlgo.ES256K)
      .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
      .addDidMethod('ethr')
      .withClientMetadata({
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:ethr'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100322',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build();
    const op = OP.builder()
      .withPresentationSignCallback(presentationSignCallback)
      .withExpiresIn(1000)
      .withHasher(hasher)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .addDidMethod('ethr')
      .withInternalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey, SigningAlgo.ES256K)
      .withRegistration({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN, ResponseType.VP_TOKEN],
        vpFormats: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: [],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100323',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build();

    const requestURI = await rp.createAuthorizationRequestURI({
      correlationId: '1234',
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
    });

    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthorizationRequestURI(requestURI.encodedUri);
    expect(parsedAuthReqURI.authorizationRequestPayload).toBeDefined();
    expect(parsedAuthReqURI.requestObjectJwt).toBeDefined();

    const verifiedAuthReqWithJWT = await op.verifyAuthorizationRequest(parsedAuthReqURI.requestObjectJwt);
    expect(verifiedAuthReqWithJWT.signer).toBeDefined();
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);
    const pex = new PresentationExchange({ allDIDs: [HOLDER_DID], allVerifiableCredentials: getVCs(), hasher });
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(
      parsedAuthReqURI.authorizationRequestPayload,
    );
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
    const verifiablePresentationResult = await pex.createVerifiablePresentation(pd[0].definition, getVCs(), presentationSignCallback, {});
    const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedAuthReqWithJWT, {
      presentationExchange: {
        verifiablePresentations: [verifiablePresentationResult.verifiablePresentation],
        vpTokenLocation: VPTokenLocation.AUTHORIZATION_RESPONSE,
        presentationSubmission: verifiablePresentationResult.presentationSubmission,
      },
    });
    expect(authenticationResponseWithJWT.response.payload).toBeDefined();
    expect(authenticationResponseWithJWT.response.idToken).toBeDefined();

    const verifiedAuthResponseWithJWT = await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
      presentationDefinitions: [{ definition: pd[0].definition, location: pd[0].location }],
    });

    expect(verifiedAuthResponseWithJWT.idToken.jwt).toBeDefined();
    expect(verifiedAuthResponseWithJWT.idToken.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
  });
});
