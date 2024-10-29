export interface OpenidFederationMetadata {
  issuer: string

  // eslint-disable-next-line  @typescript-eslint/no-explicit-any
  [x: string]: any; //We use any, so you can access properties if you know the structure

}
