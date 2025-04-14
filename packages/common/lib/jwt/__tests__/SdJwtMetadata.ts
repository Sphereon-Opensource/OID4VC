/**
 * Represents the metadata associated with a specific SD-JWT VC type.
 */
interface SdJwtTypeMetadata {
  /**
   * REQUIRED. The VC type URI.
   */
  vct: string

  /**
   * OPTIONAL. A human-readable name for the type.
   */
  name?: string

  /**
   * OPTIONAL. A human-readable description for the type.
   */
  description?: string

  /**
   * OPTIONAL. A URI of another type that this type extends.
   */
  extends?: string

  /**
   * OPTIONAL. Integrity metadata string for the 'extends' field.
   */
  ['extends#integrity']?: string

  /**
   * OPTIONAL. URL pointing towards a JSON Schema document describing the VC's structure.
   */
  schema_uri?: string

  /**
   * OPTIONAL. Integrity metadata string for the 'schema_uri' field.
   */
  ['schema_uri#integrity']?: string

  /**
   * OPTIONAL. Display metadata for various languages.
   */
  display?: Array<SdJwtTypeDisplayMetadata>

  /**
   * OPTIONAL. Metadata for the claims within the VC.
   */
  // TODO:
  claims?: Array<any>
}

/**
 * Represents display metadata for a specific language.
 */
interface SdJwtTypeDisplayMetadata {
  /**
   * REQUIRED. Language tag for the display information.
   */
  lang: string

  /**
   * REQUIRED. Human-readable name for the type.
   */
  name: string

  /**
   * OPTIONAL. Human-readable description for the type.
   */
  description?: string

  /**
   * OPTIONAL. Rendering metadata for the type.
   */
  rendering?: SdJwtTypeRenderingMetadata
}

/**
 * Contains rendering metadata for different methods.
 */
interface SdJwtTypeRenderingMetadata {
  /**
   * OPTIONAL. Simple rendering method metadata.
   */
  simple?: SdJwtSimpleRenderingMetadata

  /**
   * OPTIONAL. Metadata for SVG templates.
   */
  svg_template?: Array<SdJwtSVGTemplateMetadata>
}

/**
 * Represents metadata for simple rendering.
 */
interface SdJwtSimpleRenderingMetadata {
  /**
   * OPTIONAL. Metadata for the logo image.
   */
  logo?: SdJwtLogoMetadata

  /**
   * OPTIONAL. Background color for the credential.
   */
  background_color?: string

  /**
   * OPTIONAL. Text color for the credential.
   */
  text_color?: string
}

/**
 * Represents metadata for a logo.
 */
interface SdJwtLogoMetadata {
  /**
   * REQUIRED. URI pointing to the logo image.
   */
  uri: string

  /**
   * OPTIONAL. Integrity metadata string for the 'uri' field.
   */
  ['uri#integrity']?: string

  /**
   * OPTIONAL. Alternative text for the logo image.
   */
  alt_text?: string
}

/**
 * Represents metadata for SVG templates.
 */
interface SdJwtSVGTemplateMetadata {
  /**
   * REQUIRED. URI pointing to the SVG template.
   */
  uri: string

  /**
   * OPTIONAL. Integrity metadata string for the 'uri' field.
   */
  ['uri#integrity']?: string

  /**
   * OPTIONAL. Properties for the SVG template.
   */
  properties?: SdJwtSVGTemplateProperties
}

/**
 * Contains properties for SVG templates.
 */
interface SdJwtSVGTemplateProperties {
  /**
   * OPTIONAL. The orientation for which the SVG template is optimized.
   */
  orientation?: string

  /**
   * OPTIONAL. The color scheme for which the SVG template is optimized.
   */
  color_scheme?: string
}

// Helper function to fetch API with error handling
export async function fetchUrlWithErrorHandling(url: string): Promise<Response> {
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`${response.status}: ${response.statusText}`)
  }
  return response
}

export type SdJwtTypeHasher = (input: any, alg?: string) => string

async function validateIntegrity(input: any, integrityValue: string, hasher: SdJwtTypeHasher, alg?: string): Promise<boolean> {
  const hash = hasher(input, alg ?? 'sha256')
  return hash === integrityValue
}

// Fetch and validate Type Metadata
async function fetchSdJwtTypeMetadataFromVctUrl(vct: string, opts?: { hasher?: SdJwtTypeHasher; integrity?: string }): Promise<SdJwtTypeMetadata> {
  const url = new URL(vct)
  const wellKnownUrl = `${url.origin}/.well-known/vct${url.pathname}`

  const response = await fetchUrlWithErrorHandling(wellKnownUrl)
  const metadata: SdJwtTypeMetadata = await response.json()
  assertValidTypeMetadata(metadata, vct)
  if (opts?.integrity && opts.hasher) {
    if (!(await validateIntegrity(metadata, opts.integrity, opts.hasher))) {
      throw new Error('Integrity check failed')
    }
  }
  return metadata
}

function assertValidTypeMetadata(metadata: SdJwtTypeMetadata, vct: string): void {
  if (metadata.vct !== vct) {
    throw new Error('VCT mismatch in metadata and credential')
  }
}

/*
// Example usage
  try {
    const vct = 'https://betelgeuse.example.com/education_credential'
    const typeMetadata = await fetchSdJwtTypeMetadataFromVctUrl(vct)
    console.log('Type Metadata retrieved successfully:', typeMetadata)
  } catch (error) {
    console.error('Error fetching type metadata:', error.message)
  }
*/
