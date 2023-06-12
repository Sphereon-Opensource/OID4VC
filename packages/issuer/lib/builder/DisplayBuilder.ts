import { ImageInfo, MetadataDisplay } from '@sphereon/oid4vci-common'

export class DisplayBuilder {
  name?: string
  locale?: string
  additionalProperties: Record<string, unknown> = {}

  logo?: ImageInfo
  backgroundColor?: string
  textColor?: string

  withName(name: string) {
    this.name = name
    return this
  }

  withLocale(locale: string) {
    this.locale = locale
    return this
  }

  withLogo(logo: ImageInfo) {
    if (logo) {
      if (!logo.url) {
        throw Error(`logo without url will not work`)
      }
    }
    this.logo = logo
    return this
  }

  withBackgroundColor(backgroundColor: string) {
    this.backgroundColor = backgroundColor
    return this
  }

  withTextColor(textColor: string) {
    this.textColor = textColor
    return this
  }

  withAdditionalProperties(properties: Record<string, unknown>) {
    this.additionalProperties = properties ?? {}
    return this
  }

  addAdditionalProperty(key: string, value: unknown) {
    this.additionalProperties[key] = value
    return this
  }

  build(): MetadataDisplay {
    return {
      ...this.additionalProperties,
      ...(this.name && { name: this.name }),
      ...(this.locale && { locale: this.locale }),
      ...(this.logo && { logo: this.logo }),
      ...(this.backgroundColor && { background_color: this.backgroundColor }),
      ...(this.textColor && { text_color: this.textColor }),
    }
  }
}
