import { JWK } from '../types'

export type Jwks = {
  keys: JWK[]
}

export type JwksMetadataParams = {
  jwks?: Jwks
  jwks_uri?: string
}

/**
 * Fetches a JSON Web Key Set (JWKS) from the specified URI.
 *
 * @param jwksUri - The URI of the JWKS endpoint.
 * @returns A Promise that resolves to the JWKS object.
 * @throws Will throw an error if the fetch fails or if the response is not valid JSON.
 */
export async function joseJwksFetch(jwksUri: string): Promise<Jwks | undefined> {
  const response = await fetch(jwksUri, {
    method: 'GET',
    headers: {
      Accept: 'application/json',
    },
  })

  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`)
  }

  const jwks = await response.json()
  return jwks
}

/**
 * Extracts JSON Web Key Set (JWKS) from the provided metadata.
 * If a jwks field is provided, the JWKS will be extracted from the field.
 * If a jwks_uri is provided, the JWKS will be fetched from the URI.
 *
 * @param input - The metadata input to be validated and parsed.
 * @returns A promise that resolves to the extracted JWKS or undefined.
 * @throws {JoseJwksExtractionError} If the metadata format is invalid or no decryption key is found.
 */
export const joseJwksExtract = async (metadata: JwksMetadataParams) => {
  let jwks: Jwks | undefined = metadata.jwks?.keys[0] ? metadata.jwks : undefined

  if (!jwks && metadata.jwks_uri) {
    jwks = await joseJwksFetch(metadata.jwks_uri)
  }

  return jwks
}
