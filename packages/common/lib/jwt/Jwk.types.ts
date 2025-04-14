export interface BaseJWK {
  kty?: string
  crv?: string
  x?: string
  y?: string
  e?: string
  n?: string
}

export interface JWK extends BaseJWK {
  alg?: string
  d?: string
  dp?: string
  dq?: string
  ext?: boolean
  k?: string
  key_ops?: string[]
  kid?: string
  oth?: Array<{
    d?: string
    r?: string
    t?: string
  }>
  p?: string
  q?: string
  qi?: string
  use?: string
  x5c?: string[]
  x5t?: string
  'x5t#S256'?: string
  x5u?: string

  [propName: string]: unknown
}

export type JWKS = {
  keys: JWK[]
}
