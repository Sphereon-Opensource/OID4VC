import Tags from 'language-tags'

import { SIOPErrors } from '../types'

import { isStringNullOrEmpty } from './ObjectUtils'

export class LanguageTagUtils {
  private static readonly LANGUAGE_TAG_SEPARATOR = '#'

  /**
   * It will give back a fields which are language tag enabled. i.e. all fields with the fields names containing
   * language tags e.g. fieldName#nl-NL
   *
   * @param source is the object from which the language enabled fields and their values will be extracted.
   */
  static getAllLanguageTaggedProperties(source: object): Map<string, string> {
    return this.getLanguageTaggedPropertiesMapped(source, new Map())
  }

  /**
   * It will give back a fields which are language tag enabled and are listed in the required fields.
   *
   * @param source is the object from which the language enabled fields and their values will be extracted.
   * @param requiredFieldNames the fields which are supposed to be language enabled. These are the only fields which should be returned.
   */
  static getLanguageTaggedProperties(source: object, requiredFieldNames: Array<string>): Map<string, string> {
    const languageTagEnabledFieldsNamesMapping: Map<string, string> = new Map<string, string>()
    requiredFieldNames.forEach((value) => languageTagEnabledFieldsNamesMapping.set(value, value))
    return this.getLanguageTaggedPropertiesMapped(source, languageTagEnabledFieldsNamesMapping)
  }

  /**
   * It will give back a fields which are language tag enabled and are mapped in the required fields.
   *
   * @param source is the object from which the language enabled fields and their values will be extracted.
   * @param requiredFieldNamesMapping the fields which are supposed to be language enabled. These are the only fields which should be returned. And
   *                                  the fields names will be transformed as per the mapping provided.
   */
  static getLanguageTaggedPropertiesMapped(source: object, requiredFieldNamesMapping: Map<string, string>): Map<string, string> {
    this.assertSourceIsWorthChecking(source)
    this.assertValidTargetFieldNames(requiredFieldNamesMapping)

    const discoveredLanguageTaggedFields: Map<string, string> = new Map<string, string>()

    Object.entries(source).forEach(([key, value]) => {
      const languageTagSeparatorIndexInKey: number = key.indexOf(this.LANGUAGE_TAG_SEPARATOR)

      if (this.isFieldLanguageTagged(languageTagSeparatorIndexInKey)) {
        this.extractLanguageTaggedField(
          key,
          value as string,
          languageTagSeparatorIndexInKey,
          requiredFieldNamesMapping,
          discoveredLanguageTaggedFields,
        )
      }
    })

    return discoveredLanguageTaggedFields
  }

  private static extractLanguageTaggedField(
    key: string,
    value: string,
    languageTagSeparatorIndexInKey: number,
    languageTagEnabledFieldsNamesMapping: Map<string, string>,
    languageTaggedFields: Map<string, string>,
  ): void {
    const fieldName = this.getFieldName(key, languageTagSeparatorIndexInKey)

    const languageTag = this.getLanguageTag(key, languageTagSeparatorIndexInKey)
    if (Tags.check(languageTag)) {
      if (languageTagEnabledFieldsNamesMapping?.size) {
        if (languageTagEnabledFieldsNamesMapping.has(fieldName)) {
          languageTaggedFields.set(this.getMappedFieldName(languageTagEnabledFieldsNamesMapping, fieldName, languageTag), value)
        }
      } else {
        languageTaggedFields.set(key, value)
      }
    }
  }

  private static getMappedFieldName(languageTagEnabledFieldsNamesMapping: Map<string, string>, fieldName: string, languageTag: string): string {
    return languageTagEnabledFieldsNamesMapping.get(fieldName) + this.LANGUAGE_TAG_SEPARATOR + languageTag
  }

  private static getLanguageTag(key: string, languageTagSeparatorIndex: number): string {
    return key.substring(languageTagSeparatorIndex + 1)
  }

  private static getFieldName(key: string, languageTagSeparatorIndex: number): string {
    return key.substring(0, languageTagSeparatorIndex)
  }

  /***
   * This function checks about the field to be language-tagged.
   *
   * @param languageTagSeparatorIndex
   * @private
   */
  private static isFieldLanguageTagged(languageTagSeparatorIndex: number): boolean {
    return languageTagSeparatorIndex > 0
  }

  private static assertValidTargetFieldNames(languageTagEnabledFieldsNamesMapping: Map<string, string>): void {
    if (languageTagEnabledFieldsNamesMapping && languageTagEnabledFieldsNamesMapping.size) {
      for (const entry of languageTagEnabledFieldsNamesMapping.entries()) {
        const key = entry[0]
        const value = entry[1]
        if (isStringNullOrEmpty(key) || isStringNullOrEmpty(value)) {
          throw new Error(SIOPErrors.BAD_PARAMS + '. languageTagEnabledFieldsName must be non-null or non-empty')
        }
      }
    }
  }

  private static assertSourceIsWorthChecking(source: unknown): void {
    if (!source) {
      throw new Error(SIOPErrors.BAD_PARAMS + ' Source must be non-null i.e. not-initialized.')
    }
  }
}
