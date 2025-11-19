import { describe, expect, test } from 'vitest'
import { encodeJsonAsURI } from '../..'
import { DcqlQuery } from 'dcql'

describe('Encodings', () => {
  /*test('encodeAsUriValue', () => {
    expect(encodeAsUriValue(undefined, { a: { b: { c: 'd', e: 'f' } } })).toBe('a%5Bb%5D%5Bc%5D=d&a%5Bb%5D%5Be%5D=f');

    expect(encodeAsUriValue(undefined, { a: ['b', 'c', 'd'] })).toBe('a%5B0%5D=b&a%5B1%5D=c&a%5B2%5D=d');

    expect(
      encodeAsUriValue(undefined, {
        a: {
          b: {
            'a$s939very-2eweird-==key': {
              c: 'd',
            },
          },
        },
      })
    ).toBe('a%5Bb%5D%5Ba%24s939very-2eweird-%3D%3Dkey%5D%5Bc%5D=d');
  });*/

  test('encodeJsonAsURI', () => {
    const dcqlQuery = {
      credentials: [
        {
          id: 'bbYJTQe7YPvVx-3rLl4Aq',
          format: 'jwt_vc_json',
          meta: {
            type_values: [['OpenBadgeCredential']],
          },
          claims: [{ path: ['vp', 'verifiableCredential'] }],
        },
      ],
    } satisfies DcqlQuery.Input

    const parsedDcqlQuery = DcqlQuery.parse(dcqlQuery)
    DcqlQuery.validate(parsedDcqlQuery)

    const encoded = encodeJsonAsURI({
      dcql_query: parsedDcqlQuery,
      vp_token: ['ey...1', 'ey...2'],
      vp_token_single: 'ey...3',
    })

    expect(encoded).toBe(
      'dcql_query=%7B%22credentials%22%3A%5B%7B%22id%22%3A%22bbYJTQe7YPvVx-3rLl4Aq%22%2C%22require_cryptographic_holder_binding%22%3Atrue%2C%22multiple%22%3Afalse%2C%22format%22%3A%22jwt_vc_json%22%2C%22claims%22%3A%5B%7B%22path%22%3A%5B%22vp%22%2C%22verifiableCredential%22%5D%7D%5D%2C%22meta%22%3A%7B%22type_values%22%3A%5B%5B%22OpenBadgeCredential%22%5D%5D%7D%7D%5D%7D&vp_token=%5B%22ey...1%22%2C%22ey...2%22%5D&vp_token_single=ey...3',
    )
  })
})
