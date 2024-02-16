import { CredentialSupportedFormatV1_0_08, IssuerCredentialSubjectDisplay, IssuerMetadataV1_0_08 } from '@sphereon/oid4vci-common';
import { ICredentialStatus, W3CVerifiableCredential } from '@sphereon/ssi-types';

export function getMockData(issuerName: string): IssuerMockData | null {
  if (issuerName in mockData) {
    return mockData[issuerName];
  }
  return null;
}

export interface VciMockDataStructure {
  [issuerName: string]: IssuerMockData;
}

export interface IssuerMockData {
  metadata: {
    issuer?: string;
    token_endpoint: string;
    credential_endpoint: string;
    openid4vci_metadata: IssuerMetadataV1_0_08;
  };
  auth: {
    url: string;
    method?: string;
    request: {
      client_id: string;
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code' | 'authorization_code' | 'password';
      'pre-authorized_code'?: string;
    };
    response: {
      access_token: string;
      token_type: string;
      expires_in: number;
      c_nonce?: string;
      c_nonce_expires_in?: number;
      refresh_token?: string;
      id_token?: string;
      scope?: string;
    };
  };
  credential: {
    url: string;
    deeplink: string;
    request: {
      types?: [string];
      type?: string;
      format: 'jwt_vc' | 'ldp_vc' | 'jwt_vc_json-ld' | string;
      proof: {
        proof_type: 'jwt' | string;
        jwt: string;
      };
    };
    response: {
      format?: 'jwt_vc' | 'w3cvc-jsonld' | string;
      credential: W3CVerifiableCredential;
      acceptance_token?: string;
      c_nonce?: string;
      c_nonce_expires_in?: number;
    };
  };
}

const mockData: VciMockDataStructure = {
  spruce: {
    metadata: {
      issuer: 'https://ngi-oidc4vci-test.spruceid.xyz',
      token_endpoint: 'https://ngi-oidc4vci-testspruceid.xyz/token',
      credential_endpoint: 'https://ngi-oidc4vci-test.spruceid.xyz/credential',
      openid4vci_metadata: {
        issuer: 'https://ngi-oidc4vci-test.spruceid.xyz',
        credential_endpoint: 'https://ngi-oidc4vci-test.spruceid.xyz/credential',
        token_endpoint: 'https://ngi-oidc4vci-test.spruceid.xyz/token',
        jwks_uri: 'https://ngi-oidc4vci-test.spruceid.xyz/jwks',
        grant_types_supported: ['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
        credentials_supported: {
          OpenBadgeCredential: {
            formats: {
              jwt_vc: {
                types: ['VerifiableCredential', 'OpenBadgeCredential'],
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: ['ES256', 'ES256K'],
              },
              ldp_vc: {
                types: ['VerifiableCredential', 'OpenBadgeCredential'],
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: ['Ed25519Signature2018'],
              },
            },
          },
        },
      },
    },
    auth: {
      url: 'https://ngi-oidc4vci-test.spruceid.xyz/token',
      method: 'POST',
      request: {
        client_id: 'sphereon:ssi-wallet',
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code':
          'eyJhbGciOiJFUzI1NiJ9.eyJjcmVkZW50aWFsX3R5cGUiOlsiT3BlbkJhZGdlQ3JlZGVudGlhbCJdLCJleHAiOiIyMDIzLTA0LTE5VDExOjUzOjM4WiIsIm5vbmNlIjoiN3F4YldMcktpNTZjNjRlWjljaHJZeVUxbFVVQzMzV1YifQ.tDxAC8CsqN-DALOmY5ANEVf96fZfTzqHL4Aiq4IZzMJ-zSCrNkNBeuOK5D3RsJhSZcDMu2XvuG1RrSXJV0zHRg',
      },
      response: {
        access_token:
          'eyJhbGciOiJFUzI1NiJ9.eyJvcF9zdGF0ZSI6eyJjcmVkZW50aWFsX3R5cGUiOlsiT3BlbkJhZGdlQ3JlZGVudGlhbCJdfSwiaWF0IjoxNjgxOTA0OTUwLjAsImV4cCI6MTY4MTk5MTM1MC4wfQ.0CT_o2woWAQf_8mcPfC7uVtp_Cu8N4BLNOAgJGcQc-IcoS61QL2pArp7KdZGXGjqRmx9u4JjoVZuZHJSaDIyDg',
        token_type: 'bearer',
        expires_in: 84600,
      },
    },
    credential: {
      url: 'https://ngi-oidc4vci-test.spruceid.xyz/credential',
      deeplink:
        'openid-initiate-issuance://?issuer=https%3A%2F%2Fngi%2Doidc4vci%2Dtest%2Espruceid%2Exyz&credential_type=OpenBadgeCredential&pre-authorized_code=eyJhbGciOiJFUzI1NiJ9.eyJjcmVkZW50aWFsX3R5cGUiOlsiT3BlbkJhZGdlQ3JlZGVudGlhbCJdLCJleHAiOiIyMDIzLTA0LTIwVDA5OjA0OjM2WiIsIm5vbmNlIjoibWFibmVpT0VSZVB3V3BuRFFweEt3UnRsVVRFRlhGUEwifQ.qOZRPN8sTv_knhp7WaWte2-aDULaPZX--2i9unF6QDQNUllqDhvxgIHMDCYHCV8O2_Gj-T2x1J84fDMajE3asg&user_pin_required=false',
      request: {
        type: 'OpenBadgeCredential',
        format: 'jwt_vc',
        proof: {
          proof_type: 'jwt',
          jwt: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOa3NpTENKMWMyVWlPaUp6YVdjaUxDSnJkSGtpT2lKRlF5SXNJbU55ZGlJNkluTmxZM0F5TlRack1TSXNJbmdpT2lKclpuVmpTa0V0VEhKck9VWjBPRmx5TFVkMlQzSmpia3N3YjNkc2RqUlhNblUwU3pJeFNHZHZTVlIzSWl3aWVTSTZJalozY0ZCUE1rOUNRVXBTU0ZFMVRXdEtXVlJaV0dsQlJFUXdOMU5OTlV0amVXcDNYMkUzVUUxWmVGa2lmUSMwIn0.eyJhdWQiOiJodHRwczovL25naS1vaWRjNHZjaS10ZXN0LnNwcnVjZWlkLnh5eiIsImlhdCI6MTY4MTkxMTA2MC45NDIsImV4cCI6MTY4MTkxMTcyMC45NDIsImlzcyI6InNwaGVyZW9uOnNzaS13YWxsZXQiLCJqdGkiOiJhNjA4MzMxZi02ZmE0LTQ0ZjAtYWNkZWY5NmFjMjdmNmQ3MCJ9.NwF3_41gwnlIdd_6Uk9CczeQHzIQt6UcvTT5Cxv72j9S1vNwiY9annA2kLsjsTiR5-WMBdUhJCO7wYCtZ15mxw',
        },
      },
      response: {
        format: 'jwt_vc',
        credential:
          'eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpqd2s6ZXlKamNuWWlPaUpRTFRJMU5pSXNJbXQwZVNJNklrVkRJaXdpZUNJNklrUTNXblZZUldKRWF6bFFURzFDYkVGZldEVnVOa3N3V1dOSVdrRlZTbHBLZDFkYVVFNDBhRVppYlhjaUxDSjVJam9pYkY5b1F6Y3liREkyTFVnMlFrMURWVEp3TWxReVIxWkRSWGxoYUVWRFIyaFVaMnB2VDBkRmRESlJSU0o5IzAifQeyJleHAiOjE2ODE5OTc1MTguMCwiaXNzIjoiZGlkOmp3azpleUpqY25ZaU9pSlFMVEkxTmlJc0ltdDBlU0k2SWtWRElpd2llQ0k2SWtRM1duVllSV0pFYXpsUVRHMUNiRUZmV0RWdU5rc3dXV05JV2tGVlNscEtkMWRhVUU0MGFFWmliWGNpTENKNUlqb2liRjlvUXpjeWJESTJMVWcyUWsxRFZUSndNbFF5UjFaRFJYbGhhRVZEUjJoVVoycHZUMGRGZERKUlJTSjkiLCJuYmYiOjE2ODE5MTExMTguMCwianRpIjoidXJuOnV1aWQ6MDVhMThiMTMtYjA5Mi00MTZhLWI4OTgtY2I1OTU4N2IxNzNiIiwic3ViIjoiZGlkOmp3azpleUpoYkdjaU9pSkZVekkxTmtzaUxDSjFjMlVpT2lKemFXY2lMQ0pyZEhraU9pSkZReUlzSW1OeWRpSTZJbk5sWTNBeU5UWnJNU0lzSW5naU9pSnJablZqU2tFdFRISnJPVVowT0ZseUxVZDJUM0pqYmtzd2IzZHNkalJYTW5VMFN6SXhTR2R2U1ZSM0lpd2llU0k2SWpaM2NGQlBNazlDUVVwU1NGRTFUV3RLV1ZSWldHbEJSRVF3TjFOTk5VdGplV3AzWDJFM1VFMVplRmtpZlEiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vcHVybC5pbXNnbG9iYWwub3JnL3NwZWMvb2IvdjNwMC9jb250ZXh0Lmpzb24iXSwiaWQiOiJ1cm46dXVpZDowNWExOGIxMy1iMDkyLTQxNmEtYjg5OC1jYjU5NTg3YjE3M2IiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiT3BlbkJhZGdlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0oxYzJVaU9pSnphV2NpTENKcmRIa2lPaUpGUXlJc0ltTnlkaUk2SW5ObFkzQXlOVFpyTVNJc0luZ2lPaUpyWm5WalNrRXRUSEpyT1VaME9GbHlMVWQyVDNKamJrc3diM2RzZGpSWE1uVTBTekl4U0dkdlNWUjNJaXdpZVNJNklqWjNjRkJQTWs5Q1FVcFNTRkUxVFd0S1dWUlpXR2xCUkVRd04xTk5OVXRqZVdwM1gyRTNVRTFaZUZraWZRIiwidHlwZSI6WyJBY2hpZXZlbWVudFN1YmplY3QiXSwiYWNoaWV2ZW1lbnQiOnsiaWQiOiJ1cm46dXVpZDo1YTNmODE3Mi0zMjJiLTRhNzEtYTI1Ny1iMTFjMTA5MGI4YjkiLCJ0eXBlIjpbIkFjaGlldmVtZW50Il0sIm5hbWUiOiJKRkYgeCB2Yy1lZHUgUGx1Z0Zlc3QgMiBJbnRlcm9wZXJhYmlsaXR5IiwiZGVzY3JpcHRpb24iOiJUaGlzIGNyZWRlbnRpYWwgc29sdXRpb24gc3VwcG9ydHMgdGhlIHVzZSBvZiBPQnYzIGFuZCB3M2MgVmVyaWZpYWJsZSBDcmVkZW50aWFscyBhbmQgaXMgaW50ZXJvcGVyYWJsZSB3aXRoIGF0IGxlYXN0IHR3byBvdGhlciBzb2x1dGlvbnMuICBUaGlzIHdhcyBkZW1vbnN0cmF0ZWQgc3VjY2Vzc2Z1bGx5IGR1cmluZyBKRkYgeCB2Yy1lZHUgUGx1Z0Zlc3QgMi4iLCJjcml0ZXJpYSI6eyJuYXJyYXRpdmUiOiJTb2x1dGlvbnMgcHJvdmlkZXJzIGVhcm5lZCB0aGlzIGJhZGdlIGJ5IGRlbW9uc3RyYXRpbmcgaW50ZXJvcGVyYWJpbGl0eSBiZXR3ZWVuIG11bHRpcGxlIHByb3ZpZGVycyBiYXNlZCBvbiB0aGUgT0J2MyBjYW5kaWRhdGUgZmluYWwgc3RhbmRhcmQsIHdpdGggc29tZSBhZGRpdGlvbmFsIHJlcXVpcmVkIGZpZWxkcy4gQ3JlZGVudGlhbCBpc3N1ZXJzIGVhcm5pbmcgdGhpcyBiYWRnZSBzdWNjZXNzZnVsbHkgaXNzdWVkIGEgY3JlZGVudGlhbCBpbnRvIGF0IGxlYXN0IHR3byB3YWxsZXRzLiAgV2FsbGV0IGltcGxlbWVudGVycyBlYXJuaW5nIHRoaXMgYmFkZ2Ugc3VjY2Vzc2Z1bGx5IGRpc3BsYXllZCBjcmVkZW50aWFscyBpc3N1ZWQgYnkgYXQgbGVhc3QgdHdvIGRpZmZlcmVudCBjcmVkZW50aWFsIGlzc3VlcnMuIn0sImltYWdlIjp7ImlkIjoiaHR0cHM6Ly93M2MtY2NnLmdpdGh1Yi5pby92Yy1lZC9wbHVnZmVzdC0yLTIwMjIvaW1hZ2VzL0pGRi1WQy1FRFUtUExVR0ZFU1QyLWJhZGdlLWltYWdlLnBuZyIsInR5cGUiOiJJbWFnZSJ9fX0sImlzc3VlciI6eyJpZCI6ImRpZDpqd2s6ZXlKamNuWWlPaUpRTFRJMU5pSXNJbXQwZVNJNklrVkRJaXdpZUNJNklrUTNXblZZUldKRWF6bFFURzFDYkVGZldEVnVOa3N3V1dOSVdrRlZTbHBLZDFkYVVFNDBhRVppYlhjaUxDSjVJam9pYkY5b1F6Y3liREkyTFVnMlFrMURWVEp3TWxReVIxWkRSWGxoYUVWRFIyaFVaMnB2VDBkRmRESlJSU0o5IiwibmFtZSI6IkpvYnMgZm9yIHRoZSBGdXR1cmUgKEpGRikiLCJpbWFnZSI6eyJpZCI6Imh0dHBzOi8vdzNjLWNjZy5naXRodWIuaW8vdmMtZWQvcGx1Z2Zlc3QtMi0yMDIyL2ltYWdlcy9KRkYtVkMtRURVLVBMVUdGRVNUMi1iYWRnZS1pbWFnZS5wbmciLCJ0eXBlIjoiSW1hZ2UifSwidHlwZSI6WyJQcm9maWxlIl0sInVybCI6Imh0dHBzOi8vd3d3LmpmZi5vcmcvIn0sImlzc3VhbmNlRGF0ZSI6IjIwMjMtMDQtMTlUMTM6MzE6NThaIiwiZXhwaXJhdGlvbkRhdGUiOiIyMDIzLTA0LTIwVDEzOjMxOjU4WiIsIm5hbWUiOiJKRkYgeCB2Yy1lZHUgUGx1Z0Zlc3QgMiBJbnRlcm9wZXJhYmlsaXR5In19.8GQEtIZGTApWBpyOC3dFX8heAo3nKxb6RXzZroM3YtLVIIzWP60adgXk5IYsgsHgvoVRq9UP9igJpycH4Rxa8w',
      },
    },
  },
  walt: {
    metadata: {
      issuer: 'https://jff.walt.id/issuer-api/default/oidc/',
      token_endpoint: 'https://jff.walt.id/issuer-api/default/oidc/token',
      credential_endpoint: 'https://jff.walt.id/issuer-api/default/oidc/credential',
      openid4vci_metadata: {
        authorization_endpoint: 'https://jff.walt.id/issuer-api/default/oidc/fulfillPAR',
        token_endpoint: 'https://jff.walt.id/issuer-api/default/oidc/token',
        pushed_authorization_request_endpoint: 'https://jff.walt.id/issuer-api/default/oidc/par',
        issuer: 'https://jff.walt.id/issuer-api/default',
        jwks_uri: 'https://jff.walt.id/issuer-api/default/oidc',
        grant_types_supported: ['authorization_code', 'urn:ietf:params:oauth:grant-type:pre-authorized_code'],
        request_uri_parameter_supported: true,
        credentials_supported: {
          VerifiableId: {
            display: [
              {
                name: 'VerifiableId',
              },
            ],
            formats: {
              ldp_vc: {
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: [
                  'Ed25519Signature2018',
                  'Ed25519Signature2020',
                  'EcdsaSecp256k1Signature2019',
                  'RsaSignature2018',
                  'JsonWebSignature2020',
                  'JcsEd25519Signature2020',
                ],
                types: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableId'],
              },
              jwt_vc: {
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
                types: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableId'],
              },
            },
          },
          VerifiableDiploma: {
            display: [
              {
                name: 'VerifiableDiploma',
              },
            ],
            formats: {
              ldp_vc: {
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: [
                  'Ed25519Signature2018',
                  'Ed25519Signature2020',
                  'EcdsaSecp256k1Signature2019',
                  'RsaSignature2018',
                  'JsonWebSignature2020',
                  'JcsEd25519Signature2020',
                ],
                types: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableDiploma'],
              },
              jwt_vc: {
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
                types: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableDiploma'],
              },
            },
          },
          VerifiableVaccinationCertificate: {
            display: [
              {
                name: 'VerifiableVaccinationCertificate',
              },
            ],
            formats: {
              ldp_vc: {
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: [
                  'Ed25519Signature2018',
                  'Ed25519Signature2020',
                  'EcdsaSecp256k1Signature2019',
                  'RsaSignature2018',
                  'JsonWebSignature2020',
                  'JcsEd25519Signature2020',
                ],
                types: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableVaccinationCertificate'],
              },
              jwt_vc: {
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
                types: ['VerifiableCredential', 'VerifiableAttestation', 'VerifiableVaccinationCertificate'],
              },
            },
          },
          ProofOfResidence: {
            display: [
              {
                name: 'ProofOfResidence',
              },
            ],
            formats: {
              ldp_vc: {
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: [
                  'Ed25519Signature2018',
                  'Ed25519Signature2020',
                  'EcdsaSecp256k1Signature2019',
                  'RsaSignature2018',
                  'JsonWebSignature2020',
                  'JcsEd25519Signature2020',
                ],
                types: ['VerifiableCredential', 'VerifiableAttestation', 'ProofOfResidence'],
              },
              jwt_vc: {
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
                types: ['VerifiableCredential', 'VerifiableAttestation', 'ProofOfResidence'],
              },
            },
          },
          ParticipantCredential: {
            display: [
              {
                name: 'ParticipantCredential',
              },
            ],
            formats: {
              ldp_vc: {
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: [
                  'Ed25519Signature2018',
                  'Ed25519Signature2020',
                  'EcdsaSecp256k1Signature2019',
                  'RsaSignature2018',
                  'JsonWebSignature2020',
                  'JcsEd25519Signature2020',
                ],
                types: ['VerifiableCredential', 'ParticipantCredential'],
              },
              jwt_vc: {
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
                types: ['VerifiableCredential', 'ParticipantCredential'],
              },
            },
          },
          Europass: {
            display: [
              {
                name: 'Europass',
              },
            ],
            formats: {
              ldp_vc: {
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: [
                  'Ed25519Signature2018',
                  'Ed25519Signature2020',
                  'EcdsaSecp256k1Signature2019',
                  'RsaSignature2018',
                  'JsonWebSignature2020',
                  'JcsEd25519Signature2020',
                ],
                types: ['VerifiableCredential', 'VerifiableAttestation', 'Europass'],
              },
              jwt_vc: {
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
                types: ['VerifiableCredential', 'VerifiableAttestation', 'Europass'],
              },
            },
          },
          OpenBadgeCredential: {
            display: [
              {
                name: 'OpenBadgeCredential',
              },
            ],
            formats: {
              ldp_vc: {
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: [
                  'Ed25519Signature2018',
                  'Ed25519Signature2020',
                  'EcdsaSecp256k1Signature2019',
                  'RsaSignature2018',
                  'JsonWebSignature2020',
                  'JcsEd25519Signature2020',
                ],
                types: ['VerifiableCredential', 'OpenBadgeCredential'],
              },
              jwt_vc: {
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: ['ES256', 'ES256K', 'EdDSA', 'RS256', 'PS256'],
                types: ['VerifiableCredential', 'OpenBadgeCredential'],
              },
            },
          },
        },
        credential_issuer: {
          display: [
            {
              name: 'https://jff.walt.id/issuer-api/default',
            },
          ],
        },
        credential_endpoint: 'https://jff.walt.id/issuer-api/default/oidc/credential',
        subject_types_supported: ['public'],
      },
    },
    auth: {
      url: 'https://jff.walt.id/issuer-api/default/oidc/token',
      method: 'POST',
      request: {
        client_id: 'sphereon:ssi-wallet',
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code':
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI1NzhkZWZjOS0wMTFlLTQ3ZTAtYmQ5YS03MWFlOGU4ZTJjYzYiLCJwcmUtYXV0aG9yaXplZCI6dHJ1ZX0.uh1rX4qVqlp-YW-itLON8Zmov8t-xugCFDXlUSPuTSQ',
      },
      response: {
        access_token: '578defc9-011e-47e0-bd9a-71ae8e8e2cc6',
        refresh_token: 'zx6cildNnkqLpdCoCVnr5d77OJ6m0ugl-0sVSoEb3go',
        c_nonce: 'f06a3105-a2ed-44fc-954b-4a259703493b',
        id_token:
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI1NzhkZWZjOS0wMTFlLTQ3ZTAtYmQ5YS03MWFlOGU4ZTJjYzYifQ.MlWL2L-YucfugV573GbGFI8UHiDrGQatlekpgPq5nBY',
        token_type: 'Bearer',
        expires_in: 300,
      },
    },
    credential: {
      deeplink:
        'openid-initiate-issuance://?issuer=https%3A%2F%2Fjff.walt.id%2Fissuer-api%2Fdefault%2Foidc%2F&amp;credential_type=OpenBadgeCredential&amp;pre-authorized_code=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIwMTc4OTNjYy04ZTY3LTQxNzItYWZlOS1lODcyYmYxNDBlNWMiLCJwcmUtYXV0aG9yaXplZCI6dHJ1ZX0.ODfq2AIhOcB61dAb3zMrXBJjPJaf53zkeHh_AssYyYA&amp;user_pin_required=false',
      url: 'https://jff.walt.id/issuer-api/default/oidc/credential',
      request: {
        types: ['OpenBadgeCredential'],
        format: 'jwt_vc',
        proof: {
          proof_type: 'jwt',
          jwt: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOa3NpTENKMWMyVWlPaUp6YVdjaUxDSnJkSGtpT2lKRlF5SXNJbU55ZGlJNkluTmxZM0F5TlRack1TSXNJbmdpT2lKclpuVmpTa0V0VEhKck9VWjBPRmx5TFVkMlQzSmpia3N3YjNkc2RqUlhNblUwU3pJeFNHZHZTVlIzSWl3aWVTSTZJalozY0ZCUE1rOUNRVXBTU0ZFMVRXdEtXVlJaV0dsQlJFUXdOMU5OTlV0amVXcDNYMkUzVUUxWmVGa2lmUSMwIn0.eyJhdWQiOiJodHRwczovL2pmZi53YWx0LmlkL2lzc3Vlci1hcGkvZGVmYXVsdC9vaWRjLyIsImlhdCI6MTY4MTkxMTk0Mi4yMzgsImV4cCI6MTY4MTkxMjYwMi4yMzgsIm5vbmNlIjoiZjA2YTMxMDUtYTJlZC00NGZjLTk1NGItNGEyNTk3MDM0OTNiIiwiaXNzIjoic3BoZXJlb246c3NpLXdhbGxldCIsImp0aSI6IjA1OWM3ODA5LTlmOGYtNGE3ZS1hZDI4YTNhMTNhMGIzNmViIn0.RfiWyybxpe3nkx3b0yIsqDHQtvB1WwhDW4t0X-kijy2dsSfv2cYhSEmAzs1shg7OV4EW8fSzt_Te79xiVl6jCw',
        },
      },
      response: {
        credential:
          'eyJraWQiOiJkaWQ6andrOmV5SnJkSGtpT2lKUFMxQWlMQ0oxYzJVaU9pSnphV2NpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpYTJsa0lqb2lOMlEyWTJKbU1qUTRPV0l6TkRJM05tSXhOekl4T1RBMU5EbGtNak01TVRnaUxDSjRJam9pUm01RlZWVmhkV1J0T1RsT016QmlPREJxY3poV2REUkJiazk0ZGxKM1dIUm5VbU5MY1ROblFrbDFPQ0lzSW1Gc1p5STZJa1ZrUkZOQkluMCMwIiwidHlwIjoiSldUIiwiYWxnIjoiRWREU0EifQ.eyJpc3MiOiJkaWQ6andrOmV5SnJkSGtpT2lKUFMxQWlMQ0oxYzJVaU9pSnphV2NpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpYTJsa0lqb2lOMlEyWTJKbU1qUTRPV0l6TkRJM05tSXhOekl4T1RBMU5EbGtNak01TVRnaUxDSjRJam9pUm01RlZWVmhkV1J0T1RsT016QmlPREJxY3poV2REUkJiazk0ZGxKM1dIUm5VbU5MY1ROblFrbDFPQ0lzSW1Gc1p5STZJa1ZrUkZOQkluMCIsInN1YiI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0oxYzJVaU9pSnphV2NpTENKcmRIa2lPaUpGUXlJc0ltTnlkaUk2SW5ObFkzQXlOVFpyTVNJc0luZ2lPaUpyWm5WalNrRXRUSEpyT1VaME9GbHlMVWQyVDNKamJrc3diM2RzZGpSWE1uVTBTekl4U0dkdlNWUjNJaXdpZVNJNklqWjNjRkJQTWs5Q1FVcFNTRkUxVFd0S1dWUlpXR2xCUkVRd04xTk5OVXRqZVdwM1gyRTNVRTFaZUZraWZRIiwibmJmIjoxNjgxOTExOTk5LCJpYXQiOjE2ODE5MTE5OTksInZjIjp7InR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJPcGVuQmFkZ2VDcmVkZW50aWFsIl0sIkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9wdXJsLmltc2dsb2JhbC5vcmcvc3BlYy9vYi92M3AwL2NvbnRleHQuanNvbiJdLCJpZCI6InVybjp1dWlkOmM0YTA4MDYzLTc4ZTUtNDdkNS04NGY5LTg2YTFmNjNiYzNkYSIsImlzc3VlciI6eyJpZCI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpQUzFBaUxDSjFjMlVpT2lKemFXY2lMQ0pqY25ZaU9pSkZaREkxTlRFNUlpd2lhMmxrSWpvaU4yUTJZMkptTWpRNE9XSXpOREkzTm1JeE56SXhPVEExTkRsa01qTTVNVGdpTENKNElqb2lSbTVGVlZWaGRXUnRPVGxPTXpCaU9EQnFjemhXZERSQmJrOTRkbEozV0hSblVtTkxjVE5uUWtsMU9DSXNJbUZzWnlJNklrVmtSRk5CSW4wIiwiaW1hZ2UiOnsiaWQiOiJodHRwczovL3czYy1jY2cuZ2l0aHViLmlvL3ZjLWVkL3BsdWdmZXN0LTItMjAyMi9pbWFnZXMvSkZGLVZDLUVEVS1QTFVHRkVTVDItYmFkZ2UtaW1hZ2UucG5nIiwidHlwZSI6IkltYWdlIn0sIm5hbWUiOiJKb2JzIGZvciB0aGUgRnV0dXJlIChKRkYpIiwidHlwZSI6IlByb2ZpbGUiLCJ1cmwiOiJodHRwczovL3czYy1jY2cuZ2l0aHViLmlvL3ZjLWVkL3BsdWdmZXN0LTItMjAyMi9pbWFnZXMvSkZGLVZDLUVEVS1QTFVHRkVTVDItYmFkZ2UtaW1hZ2UucG5nIn0sImlzc3VhbmNlRGF0ZSI6IjIwMjMtMDQtMTlUMTM6NDY6MzlaIiwiaXNzdWVkIjoiMjAyMy0wNC0xOVQxMzo0NjozOVoiLCJ2YWxpZEZyb20iOiIyMDIzLTA0LTE5VDEzOjQ2OjM5WiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmp3azpleUpoYkdjaU9pSkZVekkxTmtzaUxDSjFjMlVpT2lKemFXY2lMQ0pyZEhraU9pSkZReUlzSW1OeWRpSTZJbk5sWTNBeU5UWnJNU0lzSW5naU9pSnJablZqU2tFdFRISnJPVVowT0ZseUxVZDJUM0pqYmtzd2IzZHNkalJYTW5VMFN6SXhTR2R2U1ZSM0lpd2llU0k2SWpaM2NGQlBNazlDUVVwU1NGRTFUV3RLV1ZSWldHbEJSRVF3TjFOTk5VdGplV3AzWDJFM1VFMVplRmtpZlEiLCJhY2hpZXZlbWVudCI6eyJjcml0ZXJpYSI6eyJuYXJyYXRpdmUiOiJUaGUgY29ob3J0IG9mIHRoZSBKRkYgUGx1Z2Zlc3QgMiBpbiBBdWd1c3QtTm92ZW1iZXIgb2YgMjAyMiBjb2xsYWJvcmF0ZWQgdG8gcHVzaCBpbnRlcm9wZXJhYmlsaXR5IG9mIFZDcyBpbiBlZHVjYXRpb24gZm9yd2FyZC4iLCJ0eXBlIjoiQ3JpdGVyaWEifSwiZGVzY3JpcHRpb24iOiJUaGlzIHdhbGxldCBjYW4gZGlzcGxheSB0aGlzIE9wZW4gQmFkZ2UgMy4wIiwiaWQiOiIwIiwiaW1hZ2UiOnsiaWQiOiJodHRwczovL3czYy1jY2cuZ2l0aHViLmlvL3ZjLWVkL3BsdWdmZXN0LTItMjAyMi9pbWFnZXMvSkZGLVZDLUVEVS1QTFVHRkVTVDItYmFkZ2UtaW1hZ2UucG5nIiwidHlwZSI6IkltYWdlIn0sIm5hbWUiOiJPdXIgV2FsbGV0IFBhc3NlZCBKRkYgUGx1Z2Zlc3QgIzIgMjAyMiIsInR5cGUiOiJBY2hpZXZlbWVudCJ9LCJ0eXBlIjoiQWNoaWV2ZW1lbnRTdWJqZWN0In0sIm5hbWUiOiJBY2hpZXZlbWVudCBDcmVkZW50aWFsIn0sImp0aSI6InVybjp1dWlkOmM0YTA4MDYzLTc4ZTUtNDdkNS04NGY5LTg2YTFmNjNiYzNkYSJ9.AM-lAUjCjcuQgy1QhQXctd3YrUoC2UdXvOwDHcHsi_UuHX0nt__QrYlfcwUutc9gSsz-U9SZ1e6iAGarTNVbDQ',
        format: 'jwt_vc_json-ld',
      },
    },
  },
  uniissuer: {
    metadata: {
      issuer: 'https://oidc4vc.uniissuer.io/',
      token_endpoint: 'https://oidc4vc.uniissuer.io/1.0/token',
      credential_endpoint: 'https: //oidc4vc.uniissuer.io/1.0/credential',
      openid4vci_metadata: {
        response_types_supported: ['code', 'token'],
        credentials_supported: {
          OpenBadgeCredential: {
            display: [
              {
                name: 'Open Badge V3',
                locale: 'en-US',
                logo: {
                  url: 'https: //uniissuer.io/images/logo.jpg',
                },
              },
            ],
            formats: {
              ldp_vc: {
                types: ['VerifiableCredential', 'OpenBadgeCredential'],
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: [
                  'Ed25519Signature2018',
                  'Ed25519Signature2020',
                  'EcdsaSecp256k1Signature2019',
                  'JsonWebSignature2020',
                ],
              },
              jwt_vc: {
                types: ['VerifiableCredential', 'OpenBadgeCredential'],
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: ['ES256', 'EdDSA', 'ES256K', 'RS256', 'PS256'],
              },
            },
            claims: {
              achievement: {
                mandatory: true,
                value_type: 'object',
              } as IssuerCredentialSubjectDisplay,
            },
          },
          VaccinationCertificate: {
            formats: {
              ldp_vc: {
                types: ['VerifiableCredential', 'VaccinationCertificate'],
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: [
                  'Ed25519Signature2018',
                  'Ed25519Signature2020',
                  'EcdsaSecp256k1Signature2019',
                  'JsonWebSignature2020',
                ],
              },
              jwt_vc: {
                types: ['VerifiableCredential', 'VaccinationCertificate'],
                cryptographic_binding_methods_supported: ['did'],
                cryptographic_suites_supported: ['ES256', 'EdDSA', 'ES256K', 'RS256', 'PS256'],
              },
            },
          },
        },
        credential_issuer: {
          display: [
            {
              name: 'Danube Tech',
              locale: 'en-US',
              logo: {
                url: 'https: //uniissuer.io/images/logo.jpg',
              },
            },
          ],
        },
        code_challenge_methods_supported: ['plain', 'S256'],
        grant_types_supported: ['authorization_code', 'urn:ietf:params:oauth:grant-type:pre-authorized_code'],
        token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
        issuer: 'https: //oidc4vc.uniissuer.io/',
        authorization_endpoint: 'https://oidc4vc.uniissuer.io/1.0/authorize',
        token_endpoint: 'https://oidc4vc.uniissuer.io/1.0/token',
        credential_endpoint: 'https: //oidc4vc.uniissuer.io/1.0/credential',
      },
    },
    auth: {
      url: 'https://oidc4vc.uniissuer.io/1.0/token',
      method: 'POST',
      request: {
        client_id: 'sphereon:ssi-wallet',
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': 'rQhxqvmEQef2pFChuedmDWlp6iIifUVI',
      },
      response: {
        access_token:
          'eyJraWQiOiJrZXlfMSIsInR5cCI6IkpXVCIsImFsZyI6IkVTMjU2SyJ9.eyJzdWIiOiJPcGVuV2FsbGV0IiwiYXVkIjoiT3BlbldhbGxldCIsIm5iZiI6MTY4MTkxMjg5NCwic2NvcGUiOiJPcGVuQmFkZ2VDcmVkZW50aWFsIiwiaXNzIjoiaHR0cHM6Ly91bmlpc3N1ZXIuaW8vIiwiZXhwIjoxNjgxOTEzMDc0LCJpYXQiOjE2ODE5MTI4OTQsIm5vbmNlIjoiMzhkMzZmM2ItNzJlMy00ODg2LWI2MGMtMzZiNzcwZDBlNGVhIiwianRpIjoiODkxMjhiODktNWZhMy00MjUwLTgyMGQtMGFkYzc3NjA1MWE5In0.xmR62cbZKQCQkp7aFp3LwLvTX1gV47GdB1hIxmflEZ7ShivnJx0W_bY5aGnEXmP-wSRGaC881zZKMJDDvN7frQ',
        token_type: 'Bearer',
        expires_in: 180,
        c_nonce: '38d36f3b-72e3-4886-b60c-36b770d0e4ea',
        c_nonce_expires_in: 180,
      },
    },
    credential: {
      deeplink:
        'https://oidc4vc.uniissuer.io/&credential_type=OpenBadgeCredential&pre-authorized_code=0ApoI8rxVmdQ44RIpuDbFIURIIkOhyek&user_pin_required=false',
      url: 'https://oidc4vc.uniissuer.io/1.0/credential',
      request: {
        types: ['OpenBadgeCredential'],
        format: 'jwt_vc',
        proof: {
          proof_type: 'jwt',
          jwt: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOa3NpTENKMWMyVWlPaUp6YVdjaUxDSnJkSGtpT2lKRlF5SXNJbU55ZGlJNkluTmxZM0F5TlRack1TSXNJbmdpT2lKclpuVmpTa0V0VEhKck9VWjBPRmx5TFVkMlQzSmpia3N3YjNkc2RqUlhNblUwU3pJeFNHZHZTVlIzSWl3aWVTSTZJalozY0ZCUE1rOUNRVXBTU0ZFMVRXdEtXVlJaV0dsQlJFUXdOMU5OTlV0amVXcDNYMkUzVUUxWmVGa2lmUSMwIn0.eyJhdWQiOiJodHRwczovL29pZGM0dmMudW5paXNzdWVyLmlvLyIsImlhdCI6MTY4MTkxMjgzNy40MTQsImV4cCI6MTY4MTkxMzQ5Ny40MTQsIm5vbmNlIjoiMzhkMzZmM2ItNzJlMy00ODg2LWI2MGMtMzZiNzcwZDBlNGVhIiwiaXNzIjoic3BoZXJlb246c3NpLXdhbGxldCIsImp0aSI6ImIzYWEyMmFkLWExZTItNDJjOC1iMGI4ZTdjNDgzZDg4M2U4In0.awwIJ0422HSdOsCIe8k7zjxqY6RVaHK2ItUFqbmVjqLXxWt-Mp7cXF84n9HGgC8fgGOKmjlgXdNLr_Jiio_e3g',
        },
      },
      response: {
        format: 'jwt_vc',
        credential:
          'eyJraWQiOiJkaWQ6a2V5OnpEbmFldEZmbXF5TThkRHBRTml6Q2VmOWs4SEdiSEt4NmQxYm5DdlYxZGFxeW5EUGcjekRuYWV0RmZtcXlNOGREcFFOaXpDZWY5azhIR2JIS3g2ZDFibkN2VjFkYXF5bkRQZyIsInR5cCI6IkpXVCIsImFsZyI6IkVTMjU2In0.eyJzdWIiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOa3NpTENKMWMyVWlPaUp6YVdjaUxDSnJkSGtpT2lKRlF5SXNJbU55ZGlJNkluTmxZM0F5TlRack1TSXNJbmdpT2lKclpuVmpTa0V0VEhKck9VWjBPRmx5TFVkMlQzSmpia3N3YjNkc2RqUlhNblUwU3pJeFNHZHZTVlIzSWl3aWVTSTZJalozY0ZCUE1rOUNRVXBTU0ZFMVRXdEtXVlJaV0dsQlJFUXdOMU5OTlV0amVXcDNYMkUzVUUxWmVGa2lmUSIsIm5iZiI6MTY4MTkxMjg5NSwiaXNzIjoiZGlkOmtleTp6RG5hZXRGZm1xeU04ZERwUU5pekNlZjlrOEhHYkhLeDZkMWJuQ3ZWMWRhcXluRFBnIiwidmMiOnsibmFtZSI6IkpGRiB4IHZjLWVkdSBQbHVnRmVzdCAyIEludGVyb3BlcmFiaWxpdHkiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiT3BlbkJhZGdlQ3JlZGVudGlhbCJdLCJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vcHVybC5pbXNnbG9iYWwub3JnL3NwZWMvb2IvdjNwMC9jb250ZXh0Lmpzb24iXSwiaXNzdWVyIjp7InR5cGUiOiJQcm9maWxlIiwiaWQiOiJkaWQ6a2V5OnpEbmFldEZmbXF5TThkRHBRTml6Q2VmOWs4SEdiSEt4NmQxYm5DdlYxZGFxeW5EUGciLCJuYW1lIjoiVW5pdmVyc2FsIElzc3VlciIsInVybCI6Imh0dHBzOi8vaWRjNHZjLnVuaWlzc3Vlci5pby8iLCJpbWFnZSI6Imh0dHBzOi8vdW5paXNzdWVyLmlvL2ltYWdlcy9sb2dvLmpwZyJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJhY2hpZXZlbWVudCI6eyJpbWFnZSI6eyJpZCI6Imh0dHBzOi8vdzNjLWNjZy5naXRodWIuaW8vdmMtZWQvcGx1Z2Zlc3QtMi0yMDIyL2ltYWdlcy9KRkYtVkMtRURVLVBMVUdGRVNUMi1iYWRnZS1pbWFnZS5wbmciLCJ0eXBlIjoiSW1hZ2UifSwiY3JpdGVyaWEiOnsibmFycmF0aXZlIjoiVGhlIGZpcnN0IGNvaG9ydCBvZiB0aGUgSkZGIFBsdWdmZXN0IDIgaW4gT2N0L05vdiBvZiAyMDIyIGNvbGxhYm9yYXRlZCB0byBwdXNoIGludGVyb3BlcmFiaWxpdHkgb2YgVkNzIGluIGVkdWNhdGlvbiBmb3J3YXJkLiIsInR5cGUiOiJDcml0ZXJpYSJ9LCJuYW1lIjoiVW5pdmVyc2FsIElzc3VlciBpc3N1ZWQgT3BlbiBCYWRnZSB2MyBjcmVkZW50aWFsIiwiZGVzY3JpcHRpb24iOiJXYWxsZXQgY2FuIHN0b3JlIGFuZCBkaXNwbGF5IEJhZGdlIHYzIGNyZWRlbnRpYWwiLCJ0eXBlIjoiQWNoaWV2ZW1lbnQifSwidHlwZSI6IkFjaGlldmVtZW50U3ViamVjdCJ9fX0.MEQCIENGRXVx49P1gXnRUIzaLKUeZwA9fyQKIhShjeByQDkJAiA3W89GOGUG0K6ynx1A3kpCQr25mPQfGizzVnT08C2ltw',
      },
    },
  },
  mattr: {
    metadata: {
      issuer: 'https://launchpad.mattrlabs.com',
      token_endpoint: 'https://launchpad.vii.electron.mattrlabs.io/oidc/v1/auth/token',
      credential_endpoint: 'https://launchpad.vii.electron.mattrlabs.io/oidc/v1/auth/credential',
      openid4vci_metadata: {
        authorization_endpoint: 'https://launchpad.vii.electron.mattrlabs.io/oidc/v1/auth/authorize',
        token_endpoint: 'https://launchpad.vii.electron.mattrlabs.io/oidc/v1/auth/token',
        jwks_uri: 'https://launchpad.vii.electron.mattrlabs.io/oidc/v1/auth/jwks',
        token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_jwt', 'client_secret_post', 'private_key_jwt'],
        code_challenge_methods_supported: ['S256'],
        grant_types_supported: ['authorization_code', 'urn:ietf:params:oauth:grant-type:pre-authorized_code'],
        response_modes_supported: ['form_post', 'fragment', 'query'],
        response_types_supported: ['code id_token', 'code', 'id_token', 'none'],
        scopes_supported: ['PermanentResidentCard', 'AcademicAward', 'LearnerProfile', 'OpenBadgeCredential'],
        token_endpoint_auth_signing_alg_values_supported: ['HS256', 'RS256', 'PS256', 'ES256', 'EdDSA'],
        credential_endpoint: 'https://launchpad.vii.electron.mattrlabs.io/oidc/v1/auth/credential',
        credentials_supported: {
          PermanentResidentCard: {
            formats: {
              ldp_vc: {
                name: 'Permanent Resident Card',
                description: 'Government of Kakapo PRC.',
                types: ['PermanentResidentCard'],
                binding_methods_supported: ['did'],
                cryptographic_suites_supported: ['Ed25519Signature2018'],
              } as CredentialSupportedFormatV1_0_08,
            },
          },
          AcademicAward: {
            formats: {
              ldp_vc: {
                name: 'Academic Award',
                description: 'Microcredential from the MyCreds Network.',
                types: ['AcademicAward'],
                binding_methods_supported: ['did'],
                cryptographic_suites_supported: ['Ed25519Signature2018'],
              } as CredentialSupportedFormatV1_0_08,
            },
          },
          LearnerProfile: {
            formats: {
              ldp_vc: {
                name: 'Digitary Learner Profile',
                description: 'Example',
                types: ['LearnerProfile'],
                binding_methods_supported: ['did'],
                cryptographic_suites_supported: ['Ed25519Signature2018'],
              } as CredentialSupportedFormatV1_0_08,
            },
          },
          OpenBadgeCredential: {
            formats: {
              ldp_vc: {
                name: 'JFF x vc-edu PlugFest 2',
                description: "MATTR's submission for JFF Plugfest 2",
                types: ['OpenBadgeCredential'],
                binding_methods_supported: ['did'],
                cryptographic_suites_supported: ['Ed25519Signature2018'],
              } as CredentialSupportedFormatV1_0_08,
            },
          },
        },
      },
    },
    auth: {
      url: 'https://launchpad.vii.electron.mattrlabs.io/oidc/v1/auth/token',
      method: 'POST',
      request: {
        client_id: 'sphereon:ssi-wallet',
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': 'kI_19c0PtisCJBG-ngd9mA47UCKx4uoKglUp0gqmxKt',
      },
      response: {
        access_token: 'DYaZrXQ3lCgwdU7Te93N5q1OovKXnfPDWm9Rq7fC5Ws',
        expires_in: 3600,
        scope: 'OpenBadgeCredential',
        token_type: 'Bearer',
      },
    },
    credential: {
      deeplink:
        'openid-initiate-issuance://?issuer=https://launchpad.mattrlabs.com&credential_type=OpenBadgeCredential&pre-authorized_code=g0UCOj6RAN5AwHU6gczm_GzB4_lH6GW39Z0Dl2DOOiO',
      url: 'https://launchpad.vii.electron.mattrlabs.io/oidc/v1/auth/credential',
      request: {
        type: 'OpenBadgeCredential',
        format: 'ldp_vc',
        proof: {
          proof_type: 'jwt',
          jwt: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa3AxM3N6QUFMVFN0cDV1OGtMcnl5YW5vYWtrVWtFUGZXazdvOHY3dms0RW1KI3o2TWtwMTNzekFBTFRTdHA1dThrTHJ5eWFub2Fra1VrRVBmV2s3bzh2N3ZrNEVtSiJ9.eyJhdWQiOiJodHRwczovL2xhdW5jaHBhZC5tYXR0cmxhYnMuY29tIiwiaWF0IjoxNjgxOTE0NDgyLjUxOSwiZXhwIjoxNjgxOTE1MTQyLjUxOSwiaXNzIjoic3BoZXJlb246c3NpLXdhbGxldCIsImp0aSI6ImI5NDY1ZGE5LTY4OGYtNDdjNi04MjUwNDA0ZGNiOWI5Y2E5In0.uQ8ewOfIjy_1p_Gk6PjeEWccBJnjOca1pwbTWiCAFMQX9wlIsfeUdGtXUoHjH5_PQtpwytodx7WU456_CT9iBQ',
        },
      },
      response: {
        format: 'w3cvc-jsonld',
        credential: {
          type: ['VerifiableCredential', 'VerifiableCredentialExtension', 'OpenBadgeCredential'],
          issuer: {
            id: 'did:web:launchpad.vii.electron.mattrlabs.io',
            name: 'Jobs for the Future (JFF)',
            iconUrl: 'https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png',
            image: 'https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png',
          },
          name: 'JFF x vc-edu PlugFest 2',
          description: "MATTR's submission for JFF Plugfest 2",
          credentialBranding: {
            backgroundColor: '#464c49',
          },
          issuanceDate: '2023-04-19T14:29:00.232Z',
          credentialSubject: {
            id: 'did:key:z6Mkp13szAALTStp5u8kLryyanoakkUkEPfWk7o8v7vk4EmJ',
            type: ['AchievementSubject'],
            achievement: {
              id: 'urn:uuid:bd6d9316-f7ae-4073-a1e5-2f7f5bd22922',
              name: 'JFF x vc-edu PlugFest 2 Interoperability',
              type: ['Achievement'],
              image: {
                id: 'https://w3c-ccg.github.io/vc-ed/plugfest-2-2022/images/JFF-VC-EDU-PLUGFEST2-badge-image.png',
                type: 'Image',
              },
              criteria: {
                type: 'Criteria',
                narrative:
                  'Solutions providers earned this badge by demonstrating interoperability between multiple providers based on the OBv3 candidate final standard, with some additional required fields. Credential issuers earning this badge successfully issued a credential into at least two wallets.  Wallet implementers earning this badge successfully displayed credentials issued by at least two different credential issuers.',
              },
              description:
                'This credential solutionsupports the use of OBv3 and w3c Verifiable Credentials and is interoperable with at least two other solutions.  This was demonstrated successfully during JFF x vc-edu PlugFest 2.',
            },
          },
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            {
              '@vocab': 'https://w3id.org/security/undefinedTerm#',
            },
            'https://mattr.global/contexts/vc-extensions/v1',
            'https://purl.imsglobal.org/spec/ob/v3p0/context.json',
            'https://w3id.org/vc-revocation-list-2020/v1',
          ],
          credentialStatus: {
            id: 'https://launchpad.vii.electron.mattrlabs.io/core/v1/revocation-lists/25ce0f22-975a-43f8-8936-b93983b3e8f0#39',
            type: 'RevocationList2020Status',
            revocationListIndex: '39',
            revocationListCredential: 'https://launchpad.vii.electron.mattrlabs.io/core/v1/revocation-lists/25ce0f22-975a-43f8-8936-b93983b3e8f0',
          } as ICredentialStatus,
          proof: {
            type: 'Ed25519Signature2018',
            created: '2023-04-19T14:29:01Z',
            jws: 'eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..hz5x6dCdV4C0YmpEjJx8XzpwJdD78CnEkuhx5AxfNTZavAL3HnW1m4s8nQXgejYu_a6m79Fbbakm6PZ1yEd8CA',
            proofPurpose: 'assertionMethod',
            verificationMethod: 'did:web:launchpad.vii.electron.mattrlabs.io#6BhFMCGTJg',
          },
        },
      },
    },
  },
  diwala: {
    metadata: {
      issuer: 'https://oidc4vc.diwala.io',
      token_endpoint: 'https://oidc4vc.diwala.io/token',
      credential_endpoint: 'https://oidc4vc.diwala.io/credential',
      openid4vci_metadata: {
        issuer: 'https://oidc4vc.diwala.io',
        credential_endpoint: 'https://oidc4vc.diwala.io/credential',
        token_endpoint: 'https://oidc4vc.diwala.io/token',
        jwks_uri: 'https://oidc4vc.diwala.io/jwks',
        grant_types_supported: ['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
        credentials_supported: {
          OpenBadgeCredential: {
            formats: {
              ldp_vc: {
                types: ['VerifiableCredential', 'OpenBadgeCredential'],
                cryptographic_suites_supported: ['Ed25519Signature2018'],
                cryptographic_binding_methods_supported: ['did'],
              },
            },
          },
        },
      },
    },
    auth: {
      url: 'https://oidc4vc.diwala.io/token',
      method: 'POST',
      request: {
        client_id: 'sphereon:ssi-wallet',
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code':
          'eyJhbGciOiJIUzI1NiJ9.eyJjcmVkZW50aWFsX3R5cGUiOiJPcGVuQmFkZ2VDcmVkZW50aWFsIiwiZXhwIjoxNjgxOTE1NzI5fQ.JmhU1jhMfw3f_DaIqnxurPyIW1makcwUs49Fm253z5Q',
      },
      response: {
        access_token:
          'eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6ImJNV1JnODlRTjljeVkwbTBHWW9FaWQ1YVEwcGQzUlNCM2FFUGJnZWciLCJtc0lhdCI6MTY4MTkxNjk1MjEzOSwiaWF0IjoxNjgxOTE2OTUyLCJpc3MiOiJkaXdhbGEuaW8iLCJhdWQiOiJodHRwczovL29pZGM0dmMuZGl3YWxhLmlvIiwiZXhwIjoxNzEzNDcyNzUyfQ.ERukn43tgQ-elNSZAIHo7oXLnalzHDqVh7HcDQSy6sY',
        token_type: 'bearer',
        expires_in: 31555800,
      },
    },
    credential: {
      deeplink:
        'openid-initiate-issuance://?issuer=https://oidc4vc.diwala.io&amp;credential_type=OpenBadgeCredential&amp;pre-authorized_code=eyJhbGciOiJIUzI1NiJ9.eyJjcmVkZW50aWFsX3R5cGUiOiJPcGVuQmFkZ2VDcmVkZW50aWFsIiwiZXhwIjoxNjgxOTg0NDY3fQ.fEAHKz2nuWfiYHw406iNxr-81pWkNkbi31bWsYSf6Ng',
      url: 'https://oidc4vc.diwala.io/credential',
      request: {
        type: 'OpenBadgeCredential',
        format: 'ldp_vc',
        proof: {
          proof_type: 'jwt',
          jwt: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa3AxM3N6QUFMVFN0cDV1OGtMcnl5YW5vYWtrVWtFUGZXazdvOHY3dms0RW1KI3o2TWtwMTNzekFBTFRTdHA1dThrTHJ5eWFub2Fra1VrRVBmV2s3bzh2N3ZrNEVtSiJ9.eyJhdWQiOiJodHRwczovL29pZGM0dmMuZGl3YWxhLmlvIiwiaWF0IjoxNjgxOTE1MDk1LjIwMiwiZXhwIjoxNjgxOTE1NzU1LjIwMiwiaXNzIjoic3BoZXJlb246c3NpLXdhbGxldCIsImp0aSI6IjYxN2MwM2EzLTM3MTUtNGJlMy1hYjkxNzM4MTlmYzYxNTYzIn0.KA-cHjecaYp9FSaWHkz5cqtNyhBIVT_0I7cJnpHn03T4UWFvdhjhn8Hpe-BU247enFyWOWJ6v3NQZyZgle7xBA',
        },
      },
      response: {
        credential: {
          '@context': ['https://www.w3.org/2018/credentials/v1', 'https://purl.imsglobal.org/spec/ob/v3p0/context.json'],
          id: 'urn:uuid:38beb3c1-611e-42b4-99b8-cf3e8b0fd9ae',
          type: ['VerifiableCredential', 'OpenBadgeCredential'],
          name: 'JFF x vc-edu PlugFest 2 Interoperability',
          issuer: {
            type: ['Profile'],
            id: 'did:key:z6MkrzXCdarP1kaZcJb3pmNi295wfxerDrmTqPv5c6MkP2r9',
            name: 'Jobs for the Future (JFF)',
            url: 'https://www.jff.org/',
            image: {
              id: 'https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png',
              type: 'Image',
            },
          },
          issuanceDate: '2023-04-19T14:39:13Z',
          credentialSubject: {
            type: ['AchievementSubject'],
            id: 'did:key:z6Mkp13szAALTStp5u8kLryyanoakkUkEPfWk7o8v7vk4EmJ',
            achievement: {
              id: 'urn:uuid:7e202d65-4286-4e7b-aa34-e018f05a5341',
              type: ['Achievement'],
              name: 'Diwala issued JFF x vc-edu PlugFest 2 Interoperability',
              description:
                'This credential solution supports the use of OBv3 and w3c Verifiable Credentials and is interoperable with at least two other solutions.  This was demonstrated successfully during JFF x vc-edu PlugFest 2.',
              criteria: {
                narrative:
                  'Solutions providers earned this badge by demonstrating interoperability between multiple providers based on the OBv3 candidate final standard, with some additional required fields. Credential issuers earning this badge successfully issued a credential into at least two wallets.  Wallet implementers earning this badge successfully displayed credentials issued by at least two different credential issuers.',
              },
              image: {
                id: 'https://w3c-ccg.github.io/vc-ed/plugfest-2-2022/images/JFF-VC-EDU-PLUGFEST2-badge-image.png',
                type: 'Image',
              },
            },
          },
          proof: {
            type: 'Ed25519Signature2018',
            created: '2023-04-19T14:39:13Z',
            verificationMethod: 'did:key:z6MkrzXCdarP1kaZcJb3pmNi295wfxerDrmTqPv5c6MkP2r9#z6MkrzXCdarP1kaZcJb3pmNi295wfxerDrmTqPv5c6MkP2r9',
            proofPurpose: 'assertionMethod',
            jws: 'eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..QDxjecY7YazXD6z3lsWeQ6DTGDw4KDWphzKFmkOo8DCr4ctGH7wB9ZW2EAz4qRv7s0g0O1-fXGIbAjPXfETKBw',
          },
        },
      },
    },
  },
};
