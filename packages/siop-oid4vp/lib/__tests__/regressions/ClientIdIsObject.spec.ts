import { PassBy, ResponseType, RevocationVerification, RP, Scope, SigningAlgo, SubjectType, SupportedVersion } from '../..'
import { parseJWT } from '../../helpers/jwtUtils'
import { internalSignature } from '../DidJwtTestUtils'

const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello'
// const EXAMPLE_REFERENCE_URL = 'https://rp.acme.com/siop/jwts';
const HEX_KEY = 'f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f'
const DID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0'
const KID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1'

const rp = RP.builder()
  // .withClientId('test')
  .withRedirectUri(EXAMPLE_REDIRECT_URL)
  .withRequestByValue()
  .withRevocationVerification(RevocationVerification.NEVER)
  .withCreateJwtCallback(internalSignature(HEX_KEY, DID, KID, SigningAlgo.ES256K))
  .withSupportedVersions([SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1])
  .withClientMetadata({
    idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
    passBy: PassBy.VALUE,
    requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
    responseTypesSupported: [ResponseType.ID_TOKEN],
    vpFormatsSupported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
    scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
    subjectTypesSupported: [SubjectType.PAIRWISE],
    subject_syntax_types_supported: ['did:ethr:', 'did:key:', 'did'],
  })
  .withPresentationDefinition({
    definition: {
      id: '1234-1234-1234-1234',
      input_descriptors: [
        {
          id: 'ExampleInputDescriptor',
          schema: [
            {
              uri: 'https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan',
            },
          ],
        },
      ],
    },
  })
  .build()

describe('Creating an AuthRequest with an RP from builder', () => {
  it('should have a client_id that is a string when not explicitly provided', async () => {
    // see: https://github.com/Sphereon-Opensource/SIOP-OID4VP/issues/54
    // When not supplying a clientId to the builder, the request object creates an object of the clientId
    const authRequest = await rp.createAuthorizationRequest({
      correlationId: '1',
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
    })

    const requestObjectJwt = await authRequest.requestObject?.toJwt()
    const { payload } = parseJWT(requestObjectJwt!)
    await expect(payload.client_id).toEqual(DID)
  })
})
