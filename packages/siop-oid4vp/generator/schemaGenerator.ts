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
} from 'ts-json-schema-generator'
import { Schema } from 'ts-json-schema-generator/dist/src/Schema/Schema'

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

  fs.writeFile(config.outputPath, `export const ${config.schemaId}Obj = ${schemaString};`, (err) => {
    if (err) {
      throw err
    }
  })
  return schema
}

function generateValidationCode(schemas: Schema[]) {
  const ajv = new Ajv({ schemas, code: { source: true, lines: true, esm: false }, allowUnionTypes: true, strict: false })
  const moduleCode = standaloneCode(ajv)
  fs.writeFileSync(path.join(__dirname, '../lib/schemas/validation/schemaValidation.js'), moduleCode)
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
/*
const requestOptsConf = {
  path: '../lib/authorization-request/types.ts',
  tsconfig: 'tsconfig.json',
  type: 'CreateAuthorizationRequestOpts', // Or <type-name> if you want to generate schema for that one type only
  schemaId: 'CreateAuthorizationRequestOptsSchema',
  outputPath: 'lib/schemas/AuthorizationRequestOpts.schema.ts',
  // outputConstName: 'AuthorizationRequestOptsSchema',
  skipTypeCheck: true
};*/

const responseOptsConf = {
  path: '../lib/authorization-response/types.ts',
  tsconfig: 'tsconfig.json',
  type: 'AuthorizationResponseOpts', // Or <type-name> if you want to generate schema for that one type only
  schemaId: 'AuthorizationResponseOptsSchema',
  outputPath: 'lib/schemas/AuthorizationResponseOpts.schema.ts',
  // outputConstName: 'AuthorizationResponseOptsSchema',
  skipTypeCheck: true,
}

const rPRegistrationMetadataPayload = {
  path: '../lib/types/SIOP.types.ts',
  tsconfig: 'tsconfig.json',
  type: 'RPRegistrationMetadataPayload',
  schemaId: 'RPRegistrationMetadataPayloadSchema',
  outputPath: 'lib/schemas/RPRegistrationMetadataPayload.schema.ts',
  // outputConstName: 'RPRegistrationMetadataPayloadSchema',
  skipTypeCheck: true,
}

const discoveryMetadataPayload = {
  path: '../lib/types/SIOP.types.ts',
  tsconfig: 'tsconfig.json',
  type: 'DiscoveryMetadataPayload',
  schemaId: 'DiscoveryMetadataPayloadSchema',
  outputPath: 'lib/schemas/DiscoveryMetadataPayload.schema.ts',
  // outputConstName: 'DiscoveryMetadataPayloadSchema',
  skipTypeCheck: true,
}

const authorizationRequestPayloadVID1 = {
  path: '../lib/types/SIOP.types.ts',
  tsconfig: 'tsconfig.json',
  type: 'AuthorizationRequestPayloadVID1', // Or <type-name> if you want to generate schema for that one type only
  schemaId: 'AuthorizationRequestPayloadVID1Schema',
  outputPath: 'lib/schemas/AuthorizationRequestPayloadVID1.schema.ts',
  // outputConstName: 'AuthorizationRequestPayloadSchemaVID1',
  skipTypeCheck: true,
}

const authorizationRequestPayloadVD11 = {
  path: '../lib/types/SIOP.types.ts',
  tsconfig: 'tsconfig.json',
  type: 'AuthorizationRequestPayloadVD11', // Or <type-name> if you want to generate schema for that one type only
  schemaId: 'AuthorizationRequestPayloadVD11Schema',
  outputPath: 'lib/schemas/AuthorizationRequestPayloadVD11.schema.ts',
  // outputConstName: 'AuthorizationRequestPayloadSchemaVD11',
  skipTypeCheck: true,
}

const authorizationRequestPayloadVD12OID4VPD18 = {
  path: '../lib/types/SIOP.types.ts',
  tsconfig: 'tsconfig.json',
  type: 'AuthorizationRequestPayloadVD12OID4VPD18', // Or <type-name> if you want to generate schema for that one type only
  schemaId: 'AuthorizationRequestPayloadVD12OID4VPD18Schema',
  outputPath: 'lib/schemas/AuthorizationRequestPayloadVD12OID4VPD18.schema.ts',
  // outputConstName: 'AuthorizationRequestPayloadSchemaVD11',
  skipTypeCheck: true,
}

const authorizationRequestPayloadVD12OID4VPD20 = {
  path: '../lib/types/SIOP.types.ts',
  tsconfig: 'tsconfig.json',
  type: 'AuthorizationRequestPayloadVD12OID4VPD20', // Or <type-name> if you want to generate schema for that one type only
  schemaId: 'AuthorizationRequestPayloadVD12OID4VPD20Schema',
  outputPath: 'lib/schemas/AuthorizationRequestPayloadVD12OID4VPD20.schema.ts',
  // outputConstName: 'AuthorizationRequestPayloadSchemaVD11',
  skipTypeCheck: true,
}

const schemas: Schema[] = [
  writeSchema(authorizationRequestPayloadVID1),
  writeSchema(authorizationRequestPayloadVD11),
  writeSchema(authorizationRequestPayloadVD12OID4VPD18),
  writeSchema(authorizationRequestPayloadVD12OID4VPD20),
  // writeSchema(requestOptsConf),
  writeSchema(responseOptsConf),
  writeSchema(rPRegistrationMetadataPayload),
  writeSchema(discoveryMetadataPayload),
]

generateValidationCode(schemas)
