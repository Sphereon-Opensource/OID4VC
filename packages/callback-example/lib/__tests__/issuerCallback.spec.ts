import { ICredential } from '@sphereon/ssi-types'

import { generateDid, getIssuerCallback, verifyCredential } from '../IssuerCallback'

describe('issuerCallback', () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let didKey: { didDocument: any; keyPairs: any; methodFor: any }

  beforeAll(async () => {
    didKey = await generateDid()
  })

  it('should issue a VC', async () => {
    const credential: ICredential = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential'],
      issuer: didKey.didDocument.id,
      credentialSubject: {},
      issuanceDate: new Date().toISOString(),
    }
    const vc = await getIssuerCallback(credential, didKey.keyPairs, didKey.didDocument.verificationMethod[0].id)({})
    expect(vc).toEqual({
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/security/suites/ed25519-2020/v1'],
      credentialSubject: {},
      issuanceDate: expect.any(String),
      issuer: expect.stringContaining('did:key:'),
      proof: {
        created: expect.any(String),
        proofPurpose: 'assertionMethod',
        proofValue: expect.any(String),
        type: 'Ed25519Signature2020',
        verificationMethod: expect.any(String),
      },
      type: ['VerifiableCredential'],
    })
    await expect(verifyCredential(vc, didKey.keyPairs, didKey.didDocument.verificationMethod[0].id)).resolves.toEqual(
      expect.objectContaining({ verified: true })
    )
  })
})
