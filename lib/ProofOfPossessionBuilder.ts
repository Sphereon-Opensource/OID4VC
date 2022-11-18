import { createProofOfPossession } from './functions';
import { AccessTokenResponse, Alg, EndpointMetadata, Jwt, PROOF_CANT_BE_CONSTRUCTED, ProofOfPossession, ProofOfPossessionCallbacks } from './types';

export class ProofOfPossessionBuilder {
  private readonly proof?: ProofOfPossession;
  private readonly callbacks?: ProofOfPossessionCallbacks;

  private kid: string;
  private clientId?: string;
  private issuer?: string;
  private jwt?: Jwt;
  private alg?: string;
  private jti?: string;
  private cNonce?: string;

  private constructor(opts: {
    proof?: ProofOfPossession;
    callbacks?: ProofOfPossessionCallbacks;
    accessTokenResponse?: AccessTokenResponse;
    jwt?: Jwt;
  }) {
    this.proof = opts.proof;
    this.callbacks = opts.callbacks;
    if (opts.jwt) {
      this.withJwt(opts.jwt);
    }
    if (opts.accessTokenResponse) {
      this.withAccessTokenResponse(opts.accessTokenResponse);
    }
  }

  static fromJwt(jwt: Jwt, callbacks: ProofOfPossessionCallbacks): ProofOfPossessionBuilder {
    return new ProofOfPossessionBuilder({ callbacks, jwt });
  }

  static fromAccessTokenResponse(accessTokenResponse: AccessTokenResponse, callbacks: ProofOfPossessionCallbacks): ProofOfPossessionBuilder {
    return new ProofOfPossessionBuilder({ callbacks, accessTokenResponse });
  }

  static fromProof(proof: ProofOfPossession): ProofOfPossessionBuilder {
    return new ProofOfPossessionBuilder({ proof });
  }

  withClientId(clientId: string): ProofOfPossessionBuilder {
    this.clientId = clientId;
    return this;
  }

  withKid(kid: string): ProofOfPossessionBuilder {
    this.kid = kid;
    return this;
  }

  withIssuer(issuer: string): ProofOfPossessionBuilder {
    this.issuer = issuer;
    return this;
  }

  withAlg(alg: Alg | string): ProofOfPossessionBuilder {
    this.alg = alg;
    return this;
  }

  withJti(jti: string): ProofOfPossessionBuilder {
    this.jti = jti;
    return this;
  }

  withAccessTokenNonce(cNonce: string): ProofOfPossessionBuilder {
    this.cNonce = cNonce;
    return this;
  }

  withAccessTokenResponse(accessToken: AccessTokenResponse): ProofOfPossessionBuilder {
    this.withAccessTokenNonce(accessToken.c_nonce);
    return this;
  }

  withEndpointMetadata(endpointMetadata: EndpointMetadata): ProofOfPossessionBuilder {
    this.withIssuer(endpointMetadata.issuer);
    return this;
  }

  withJwt(jwt: Jwt): ProofOfPossessionBuilder {
    if (!jwt) {
      throw new Error(`No JWT provided`);
    }
    this.jwt = jwt;
    if (jwt.header) {
      this.withKid(jwt.header.kid);
      this.withAlg(jwt.header.alg);
    }
    if (jwt.payload) {
      this.withClientId(jwt.payload.iss);
      this.withIssuer(jwt.payload.aud);
      this.withJti(jwt.payload.jti);
      this.withAccessTokenNonce(jwt.payload.nonce);
    }
    return this;
  }

  public async build(): Promise<ProofOfPossession> {
    if (this.proof) {
      return Promise.resolve(this.proof);
    } else if (this.callbacks) {
      return await createProofOfPossession(
        this.callbacks,
        {
          kid: this.kid,
          jti: this.jti,
          alg: this.alg,
          issuer: this.issuer,
          clientId: this.clientId,
          nonce: this.cNonce,
        },
        this.jwt
      );
    }
    throw new Error(PROOF_CANT_BE_CONSTRUCTED);
  }
}
