import { LanguageTagUtils } from '../..'

describe('Language tag util should', () => {
  it('return no lingually tagged fields if there are no lingually tagged fields in the source object', async () => {
    expect.assertions(1)
    const source = { nonLanguageTaggedFieldName: 'value' }
    expect(LanguageTagUtils.getAllLanguageTaggedProperties(source)).toEqual(new Map<string, string>())
  })

  it('return all lingually tagged fields if there are lingually tagged fields in the source object', async () => {
    expect.assertions(1)
    const source = {
      FieldNameWithoutLanguageTag: 'value',
      'FieldNameWithLanguageTag#nl-NL': 'dutchValue',
      'FieldNameWithLanguageTag#en-US': 'englishValue',
    }

    const expectedTaggedFields = new Map<string, string>()
    expectedTaggedFields.set('FieldNameWithLanguageTag#nl-NL', 'dutchValue')
    expectedTaggedFields.set('FieldNameWithLanguageTag#en-US', 'englishValue')

    const allLanguageTaggedProperties = LanguageTagUtils.getAllLanguageTaggedProperties(source)
    expect(allLanguageTaggedProperties).toEqual(expectedTaggedFields)
  })

  it('return all lingually tagged fields regardless of capitalization if there are lingually tagged fields in the source object', async () => {
    expect.assertions(1)
    const source = {
      FieldNameWithoutLanguageTag: 'value',
      'FieldNameWithLanguageTag#nl-nl': 'dutchValue',
      'FieldNameWithLanguageTag#en-US': 'englishValue',
    }

    const expectedTaggedFields = new Map<string, string>()
    expectedTaggedFields.set('FieldNameWithLanguageTag#nl-nl', 'dutchValue')
    expectedTaggedFields.set('FieldNameWithLanguageTag#en-US', 'englishValue')

    const allLanguageTaggedProperties = LanguageTagUtils.getAllLanguageTaggedProperties(source)
    expect(allLanguageTaggedProperties).toEqual(expectedTaggedFields)
  })

  it('return all lingually tagged fields if there are only lingually tagged fields in the source object', async () => {
    expect.assertions(1)
    const source = {
      'FieldNameWithLanguageTag#nl-NL': 'dutchValue',
      'FieldNameWithLanguageTag#en-US': 'englishValue',
    }
    const expectedTaggedFields = new Map<string, string>()
    expectedTaggedFields.set('FieldNameWithLanguageTag#nl-NL', 'dutchValue')
    expectedTaggedFields.set('FieldNameWithLanguageTag#en-US', 'englishValue')

    const allLanguageTaggedProperties = LanguageTagUtils.getAllLanguageTaggedProperties(source)
    expect(allLanguageTaggedProperties).toEqual(expectedTaggedFields)
  })

  it('return all lingually tagged fields if there are multiple lingually tagged fields in the source object but no non-lingually tagged fields', async () => {
    expect.assertions(1)
    const source = {
      'FieldNameWithLanguageTag1#nl-NL': 'dutchValue',
      'FieldNameWithLanguageTag2#en-US': 'englishValue',
    }
    const expectedTaggedFields = new Map<string, string>()
    expectedTaggedFields.set('FieldNameWithLanguageTag1#nl-NL', 'dutchValue')
    expectedTaggedFields.set('FieldNameWithLanguageTag2#en-US', 'englishValue')

    const allLanguageTaggedProperties = LanguageTagUtils.getAllLanguageTaggedProperties(source)
    expect(allLanguageTaggedProperties).toEqual(expectedTaggedFields)
  })

  it('return all lingually tagged fields if there are multiple lingually tagged fields in multiple languages in the source object but no non-lingually tagged fields', async () => {
    expect.assertions(1)
    const source = {
      'FieldNameWithLanguageTag1#nl-NL': 'dutchValue',
      'FieldNameWithLanguageTag1#en-US': 'englishValue',
      'FieldNameWithLanguageTag2#nl-NL': 'dutchValue',
      'FieldNameWithLanguageTag2#en-US': 'englishValue',
    }
    const expectedTaggedFields = new Map<string, string>()
    expectedTaggedFields.set('FieldNameWithLanguageTag1#nl-NL', 'dutchValue')
    expectedTaggedFields.set('FieldNameWithLanguageTag1#en-US', 'englishValue')
    expectedTaggedFields.set('FieldNameWithLanguageTag2#nl-NL', 'dutchValue')
    expectedTaggedFields.set('FieldNameWithLanguageTag2#en-US', 'englishValue')

    const allLanguageTaggedProperties = LanguageTagUtils.getAllLanguageTaggedProperties(source)
    expect(allLanguageTaggedProperties).toEqual(expectedTaggedFields)
  })

  it('return all lingually tagged fields if there are multiple lingually tagged fields in multiple languages in the source object but there is a non-lingually tagged field', async () => {
    expect.assertions(1)
    const source = {
      nonLanguageTaggedFieldName: 'value',
      'FieldNameWithLanguageTag1#nl-NL': 'dutchValue',
      'FieldNameWithLanguageTag1#en-US': 'englishValue',
      'FieldNameWithLanguageTag2#nl-NL': 'dutchValue',
      'FieldNameWithLanguageTag2#en-US': 'englishValue',
    }
    const expectedTaggedFields = new Map<string, string>()
    expectedTaggedFields.set('FieldNameWithLanguageTag1#nl-NL', 'dutchValue')
    expectedTaggedFields.set('FieldNameWithLanguageTag1#en-US', 'englishValue')
    expectedTaggedFields.set('FieldNameWithLanguageTag2#nl-NL', 'dutchValue')
    expectedTaggedFields.set('FieldNameWithLanguageTag2#en-US', 'englishValue')

    const allLanguageTaggedProperties = LanguageTagUtils.getAllLanguageTaggedProperties(source)
    expect(allLanguageTaggedProperties).toEqual(expectedTaggedFields)
  })

  it('return all lingually tagged fields if there are multiple lingually tagged fields in multiple languages in the source object but there are non-lingually tagged fields', async () => {
    expect.assertions(1)
    const source = {
      nonLanguageTaggedFieldName: 'value',
      nonLanguageTaggedFieldName2: 'value',
      'FieldNameWithLanguageTag1#nl-NL': 'dutchValue',
      'FieldNameWithLanguageTag1#en-US': 'englishValue',
      'FieldNameWithLanguageTag2#nl-NL': 'dutchValue',
      'FieldNameWithLanguageTag2#en-US': 'englishValue',
    }

    const expectedTaggedFields = new Map<string, string>()
    expectedTaggedFields.set('FieldNameWithLanguageTag1#nl-NL', 'dutchValue')
    expectedTaggedFields.set('FieldNameWithLanguageTag1#en-US', 'englishValue')
    expectedTaggedFields.set('FieldNameWithLanguageTag2#nl-NL', 'dutchValue')
    expectedTaggedFields.set('FieldNameWithLanguageTag2#en-US', 'englishValue')

    const allLanguageTaggedProperties = LanguageTagUtils.getAllLanguageTaggedProperties(source)
    expect(allLanguageTaggedProperties).toEqual(expectedTaggedFields)
  })

  it('return no lingually tagged fields if there are incorrect lingually tagged fields in the source object', async () => {
    expect.assertions(1)
    const source = {
      'FieldNameWithLanguageTag2#en-EN': 'englishValue',
    }

    const allLanguageTaggedProperties = LanguageTagUtils.getAllLanguageTaggedProperties(source)
    expect(allLanguageTaggedProperties).toEqual(new Map<string, string>())
  })

  it('return non-mapped lingually tagged fields if there are multiple lingually tagged fields in multiple languages in the source object but there are non-lingually tagged fields as well', async () => {
    expect.assertions(1)
    const source = {
      nonLanguageTaggedFieldName: 'value',
      nonLanguageTaggedFieldName2: 'value',
      'FieldNameWithLanguageTag1#nl-NL': 'dutchValue',
      'FieldNameWithLanguageTag1#en-US': 'englishValue',
      'FieldNameWithLanguageTag2#nl-NL': 'dutchValue',
      'FieldNameWithLanguageTag2#en-US': 'englishValue',
    }
    const expectedTaggedFields = new Map<string, string>()
    expectedTaggedFields.set('FieldNameWithLanguageTag1#nl-NL', 'dutchValue')
    expectedTaggedFields.set('FieldNameWithLanguageTag1#en-US', 'englishValue')
    expectedTaggedFields.set('FieldNameWithLanguageTag2#nl-NL', 'dutchValue')
    expectedTaggedFields.set('FieldNameWithLanguageTag2#en-US', 'englishValue')

    const allLanguageTaggedProperties = LanguageTagUtils.getLanguageTaggedProperties(source, [
      'FieldNameWithLanguageTag1',
      'FieldNameWithLanguageTag2',
    ])
    expect(allLanguageTaggedProperties).toEqual(expectedTaggedFields)
  })

  it('return only desired non-mapped lingually tagged fields if there are multiple lingually tagged fields in multiple languages in the source object but there are non-lingually tagged fields as well', async () => {
    expect.assertions(1)
    const source = {
      nonLanguageTaggedFieldName: 'value',
      nonLanguageTaggedFieldName2: 'value',
      'FieldNameWithLanguageTag1#nl-NL': 'dutchValue',
      'FieldNameWithLanguageTag1#en-US': 'englishValue',
      'FieldNameWithLanguageTag2#nl-NL': 'dutchValue',
      'FieldNameWithLanguageTag2#en-US': 'englishValue',
    }
    const expectedTaggedFields = new Map<string, string>()
    expectedTaggedFields.set('FieldNameWithLanguageTag1#nl-NL', 'dutchValue')
    expectedTaggedFields.set('FieldNameWithLanguageTag1#en-US', 'englishValue')

    const allLanguageTaggedProperties = LanguageTagUtils.getLanguageTaggedProperties(source, ['FieldNameWithLanguageTag1'])
    expect(allLanguageTaggedProperties).toEqual(expectedTaggedFields)
  })

  it('return only desired mapped lingually tagged fields if there are multiple lingually tagged fields in multiple languages in the source object but there are non-lingually tagged fields as well', async () => {
    expect.assertions(1)
    const source = {
      nonLanguageTaggedFieldName: 'value',
      nonLanguageTaggedFieldName2: 'value',
      'FieldNameWithLanguageTag1#nl-NL': 'dutchValue',
      'FieldNameWithLanguageTag1#en-US': 'englishValue',
      'FieldNameWithLanguageTag2#nl-NL': 'dutchValue',
      'FieldNameWithLanguageTag2#en-US': 'englishValue',
    }
    const expectedTaggedFields = new Map<string, string>()
    expectedTaggedFields.set('field_name_with_Language_tag_1#nl-NL', 'dutchValue')
    expectedTaggedFields.set('field_name_with_Language_tag_1#en-US', 'englishValue')

    const languageTagEnabledFieldsNamesMapping = new Map<string, string>()
    languageTagEnabledFieldsNamesMapping.set('FieldNameWithLanguageTag1', 'field_name_with_Language_tag_1')

    const allLanguageTaggedProperties = LanguageTagUtils.getLanguageTaggedPropertiesMapped(source, languageTagEnabledFieldsNamesMapping)
    expect(allLanguageTaggedProperties).toEqual(expectedTaggedFields)
  })

  it('throw error if list is null', async () => {
    expect.assertions(1)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => LanguageTagUtils.getLanguageTaggedProperties({}, null as any)).toThrowError()
  })

  it('return empty if list is given but not effective', async () => {
    expect.assertions(1)
    const result = await LanguageTagUtils.getLanguageTaggedProperties({}, [])
    expect(result).toEqual(new Map<string, string>())
  })

  it('throw error if list is given but no proper field names', async () => {
    expect.assertions(1)
    await expect(() => LanguageTagUtils.getLanguageTaggedProperties({}, [''])).toThrowError()
  })

  it('do not throw error if mapping is null', async () => {
    expect.assertions(1)
    expect(LanguageTagUtils.getLanguageTaggedPropertiesMapped({}, null as any)).toEqual(new Map<string, string>())
  })

  it('return empty map if mapping is given but not effective', async () => {
    expect.assertions(1)
    const result = await LanguageTagUtils.getLanguageTaggedPropertiesMapped({}, new Map<string, string>())
    expect(result).toEqual(new Map<string, string>())
  })

  it('throw error if mapping is given but no proper names', async () => {
    expect.assertions(1)
    const languageTagEnabledFieldsNamesMapping: Map<string, string> = new Map<string, string>()
    languageTagEnabledFieldsNamesMapping.set(null as any, 'valid')
    await expect(() => LanguageTagUtils.getLanguageTaggedPropertiesMapped({}, languageTagEnabledFieldsNamesMapping)).toThrowError()
  })

  it('throw error if mapping is given but no proper field names', async () => {
    expect.assertions(1)
    const languageTagEnabledFieldsNamesMapping: Map<string, string> = new Map<string, string>()
    languageTagEnabledFieldsNamesMapping.set('', 'valid')
    await expect(() => LanguageTagUtils.getLanguageTaggedPropertiesMapped({}, languageTagEnabledFieldsNamesMapping)).toThrowError()
  })

  it('throw error if mapping is given but no mapped names', async () => {
    expect.assertions(1)
    const languageTagEnabledFieldsNamesMapping: Map<string, string> = new Map<string, string>()
    languageTagEnabledFieldsNamesMapping.set('valid', null as any)
    await expect(() => LanguageTagUtils.getLanguageTaggedPropertiesMapped({}, languageTagEnabledFieldsNamesMapping)).toThrowError()
  })

  it('throw error if mapping is given but no proper mapped names', async () => {
    expect.assertions(1)
    const languageTagEnabledFieldsNamesMapping: Map<string, string> = new Map<string, string>()
    languageTagEnabledFieldsNamesMapping.set('valid', '')
    await expect(() => LanguageTagUtils.getLanguageTaggedPropertiesMapped({}, languageTagEnabledFieldsNamesMapping)).toThrowError()
  })
})
