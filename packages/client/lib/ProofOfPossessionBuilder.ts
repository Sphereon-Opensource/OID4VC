import {
  AccessTokenResponse,
  Alg,
  EndpointMetadata,
  JWK,
  Jwt,
  NO_JWT_PROVIDED,
  OpenId4VCIVersion,
  PROOF_CANT_BE_CONSTRUCTED,
  ProofOfPossession,
  ProofOfPossessionCallbacks,
  Typ,
} from '@sphereon/oid4vci-common';

import { createProofOfPossession } from './functions';

export class ProofOfPossessionBuilder<DIDDoc> {
  private readonly proof?: ProofOfPossession;
  private readonly callbacks?: ProofOfPossessionCallbacks<DIDDoc>;
  private readonly version: OpenId4VCIVersion;

  private kid?: string;
  private jwk?: JWK;
  private clientId?: string;
  private issuer?: string;
  private jwt?: Jwt;
  private alg?: string;
  private jti?: string;
  private cNonce?: string;
  private typ?: Typ;

  private constructor({
    proof,
    callbacks,
    jwt,
    accessTokenResponse,
    version,
  }: {
    proof?: ProofOfPossession;
    callbacks?: ProofOfPossessionCallbacks<DIDDoc>;
    accessTokenResponse?: AccessTokenResponse;
    jwt?: Jwt;
    version: OpenId4VCIVersion;
  }) {
    this.proof = proof;
    this.callbacks = callbacks;
    this.version = version;
    if (jwt) {
      this.withJwt(jwt);
    } else {
      this.withTyp(version < OpenId4VCIVersion.VER_1_0_11 ? 'jwt' : 'openid4vci-proof+jwt');
    }
    if (accessTokenResponse) {
      this.withAccessTokenResponse(accessTokenResponse);
    }
  }

  static fromJwt<DIDDoc>({
    jwt,
    callbacks,
    version,
  }: {
    jwt: Jwt;
    callbacks: ProofOfPossessionCallbacks<DIDDoc>;
    version: OpenId4VCIVersion;
  }): ProofOfPossessionBuilder<DIDDoc> {
    return new ProofOfPossessionBuilder({ callbacks, jwt, version });
  }

  static fromAccessTokenResponse<DIDDoc>({
    accessTokenResponse,
    callbacks,
    version,
  }: {
    accessTokenResponse: AccessTokenResponse;
    callbacks: ProofOfPossessionCallbacks<DIDDoc>;
    version: OpenId4VCIVersion;
  }): ProofOfPossessionBuilder<DIDDoc> {
    return new ProofOfPossessionBuilder({ callbacks, accessTokenResponse, version });
  }

  static fromProof<DIDDoc>(proof: ProofOfPossession, version: OpenId4VCIVersion): ProofOfPossessionBuilder<DIDDoc> {
    return new ProofOfPossessionBuilder({ proof, version });
  }

  withClientId(clientId: string): this {
    this.clientId = clientId;
    return this;
  }

  withKid(kid: string): this {
    this.kid = kid;
    return this;
  }

  withJWK(jwk: JWK): this {
    this.jwk = jwk;
    return this;
  }

  withIssuer(issuer: string): this {
    this.issuer = issuer;
    return this;
  }

  withAlg(alg: Alg | string): this {
    this.alg = alg;
    return this;
  }

  withJti(jti: string): this {
    this.jti = jti;
    return this;
  }

  withTyp(typ: Typ): this {
    if (this.version >= OpenId4VCIVersion.VER_1_0_11) {
      if (!!typ && typ !== 'openid4vci-proof+jwt') {
        throw Error('typ must be openid4vci-proof+jwt for version 1.0.11 and up');
      }
    } else {
      if (!!typ && typ !== 'jwt') {
        throw Error('typ must be jwt for version 1.0.10 and below');
      }
    }
    this.typ = typ;
    return this;
  }

  withAccessTokenNonce(cNonce: string): this {
    this.cNonce = cNonce;
    return this;
  }

  withAccessTokenResponse(accessToken: AccessTokenResponse): this {
    if (accessToken.c_nonce) {
      this.withAccessTokenNonce(accessToken.c_nonce);
    }
    return this;
  }

  withEndpointMetadata(endpointMetadata: EndpointMetadata): this {
    this.withIssuer(endpointMetadata.issuer);
    return this;
  }

  withJwt(jwt: Jwt): this {
    if (!jwt) {
      throw new Error(NO_JWT_PROVIDED);
    }
    this.jwt = jwt;
    if (!jwt.header) {
      throw Error(`No JWT header present`);
    } else if (!jwt.payload) {
      throw Error(`No JWT payload present`);
    }

    if (jwt.header.kid) {
      this.withKid(jwt.header.kid);
    }
    if (jwt.header.typ) {
      this.withTyp(jwt.header.typ as Typ);
    }
    if (this.version >= OpenId4VCIVersion.VER_1_0_11) {
      this.withTyp('openid4vci-proof+jwt');
    }
    this.withAlg(jwt.header.alg);

    if (Array.isArray(jwt.payload.aud)) {
      // Rather do this than take the first value, as it might be very hard to figure out why something is failing
      throw Error('We cannot handle multiple aud values currently');
    }

    if (jwt.payload) {
      if (jwt.payload.iss) this.withClientId(jwt.payload.iss);
      if (jwt.payload.aud) this.withIssuer(jwt.payload.aud);
      if (jwt.payload.jti) this.withJti(jwt.payload.jti);
      if (jwt.payload.nonce) this.withAccessTokenNonce(jwt.payload.nonce);
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
          typ: this.typ ?? (this.version < OpenId4VCIVersion.VER_1_0_11 ? 'jwt' : 'openid4vci-proof+jwt'),
          kid: this.kid,
          jwk: this.jwk,
          jti: this.jti,
          alg: this.alg,
          issuer: this.issuer,
          clientId: this.clientId,
          nonce: this.cNonce,
        },
        this.jwt,
      );
    }
    throw new Error(PROOF_CANT_BE_CONSTRUCTED);
  }
}
