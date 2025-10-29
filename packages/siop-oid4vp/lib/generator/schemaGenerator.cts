import fs from 'fs'
import path from 'path'
import Ajv from 'ajv'
import standaloneCode from 'ajv/dist/standalone'
import {
  BaseType,
  createFormatter,
  createParser,
  createProgram,
  Definition,
  FunctionType,
  MutableTypeFormatter,
  SchemaGenerator,
  SubTypeFormatter,
  Schema
} from 'ts-json-schema-generator'

class CustomTypeFormatter implements SubTypeFormatter {
  public supportsType(type: FunctionType): boolean {
    return type instanceof FunctionType
  }

  public getDefinition(): Definition {
    // Return a custom schema for the function property.
    return {
      properties: {
        isFunction: {
          type: 'boolean',
          const: true,
        },
      },
    }
  }

  public getChildren(): BaseType[] {
    return []
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function writeSchema(config: any): Schema {
  const formatter = createFormatter(config, (fmt: MutableTypeFormatter) => {
    fmt.addTypeFormatter(new CustomTypeFormatter())
  })

  const program = createProgram(config)
  const schema = new SchemaGenerator(program, createParser(program, config), formatter, config).createSchema(config.type)

  let schemaString = JSON.stringify(schema, null, 2)
  schemaString = correctSchema(schemaString)

  fs.writeFile(path.join(__dirname, config.outputPath), `export const ${config.schemaId}Obj = ${schemaString};`, (err) => {
    if (err) {
      throw err
    }
  })
  return schema
}

function generateValidationCode(schemas: Schema[]) {
  const ajv = new Ajv({ schemas, code: { source: true, lines: true, esm: false }, allowUnionTypes: true, strict: false })
  const moduleCode = standaloneCode(ajv)
  fs.writeFileSync(path.join(__dirname, '../schemas/validation/schemaValidation.cjs'), moduleCode)
}

function correctSchema(schemaString: string) {
  return schemaString.replace(
    '"SuppliedSignature": {\n' +
      '      "type": "object",\n' +
      '      "properties": {\n' +
      '        "withSignature": {\n' +
      '          "properties": {\n' +
      '            "isFunction": {\n' +
      '              "type": "boolean",\n' +
      '              "const": true\n' +
      '            }\n' +
      '          }\n' +
      '        },\n' +
      '        "did": {\n' +
      '          "type": "string"\n' +
      '        },\n' +
      '        "kid": {\n' +
      '          "type": "string"\n' +
      '        }\n' +
      '      },\n' +
      '      "required": [\n' +
      '        "withSignature",\n' +
      '        "did",\n' +
      '        "kid"\n' +
      '      ],\n' +
      '      "additionalProperties": false\n' +
      '    },',
    '"SuppliedSignature": {\n' +
      '      "type": "object",\n' +
      '      "properties": {\n' +
      '        "did": {\n' +
      '          "type": "string"\n' +
      '        },\n' +
      '        "kid": {\n' +
      '          "type": "string"\n' +
      '        }\n' +
      '      },\n' +
      '      "required": [\n' +
      '        "did",\n' +
      '        "kid"\n' +
      '      ],\n' +
      '      "additionalProperties": true\n' +
      '    },',
  )
}

const responseOptsConf = {
  path: '../authorization-response/types.ts',
  tsconfig: 'tsconfig.json',
  type: 'AuthorizationResponseOpts', // Or <type-name> if you want to generate schema for that one type only
  schemaId: 'AuthorizationResponseOptsSchema',
  outputPath: '../schemas/AuthorizationResponseOpts.schema.ts',
  skipTypeCheck: true,
}

const rPRegistrationMetadataPayload = {
  path: '../types/SIOP.types.ts',
  tsconfig: 'tsconfig.json',
  type: 'RPRegistrationMetadataPayload',
  schemaId: 'RPRegistrationMetadataPayloadSchema',
  outputPath: '../schemas/RPRegistrationMetadataPayload.schema.ts',
  skipTypeCheck: true,
}

const discoveryMetadataPayload = {
  path: '../types/SIOP.types.ts',
  tsconfig: 'tsconfig.json',
  type: 'DiscoveryMetadataPayload',
  schemaId: 'DiscoveryMetadataPayloadSchema',
  outputPath: '../schemas/DiscoveryMetadataPayload.schema.ts',
  skipTypeCheck: true,
}

const authorizationRequestPayloadV1 = {
  path: '../types/SIOP.types.ts',
  tsconfig: 'tsconfig.json',
  type: 'AuthorizationRequestPayloadV1', // Or <type-name> if you want to generate schema for that one type only
  schemaId: 'AuthorizationRequestPayloadV1Schema',
  outputPath: '../schemas/AuthorizationRequestPayloadV1.schema.ts',
  skipTypeCheck: true,
}

const authorizationRequestPayloadD28 = {
  path: '../types/SIOP.types.ts',
  tsconfig: 'tsconfig.json',
  type: 'AuthorizationRequestPayloadD28', // Or <type-name> if you want to generate schema for that one type only
  schemaId: 'AuthorizationRequestPayloadD28Schema',
  outputPath: '../schemas/AuthorizationRequestPayloadD28.schema.ts',
  skipTypeCheck: true,
}

const schemas: Schema[] = [
  writeSchema(authorizationRequestPayloadV1),
  writeSchema(authorizationRequestPayloadD28),
  writeSchema(responseOptsConf),
  writeSchema(rPRegistrationMetadataPayload),
  writeSchema(discoveryMetadataPayload),
]

generateValidationCode(schemas)
