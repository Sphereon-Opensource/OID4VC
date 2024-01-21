import { encodeJsonAsURI } from '../../src';

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
    const encoded = encodeJsonAsURI(
      {
        presentation_submission: {
          id: 'bbYJTQe7YPvVx-3rLl4Aq',
          definition_id: '000fc41b-2859-4fc3-b797-510492a9479a',
          descriptor_map: [
            {
              id: 'OpenBadgeCredential',
              format: 'jwt_vp',
              path: '$',
              path_nested: {
                id: 'OpenBadgeCredential',
                format: 'jwt_vc_json',
                path: '$.vp.verifiableCredential[0]',
              },
            },
          ],
        },
        vp_token: ['ey...1', 'ey...2'],
        vp_token_single: 'ey...3',
      },
      /*{ arraysWithIndex: ['presentation_submission', 'vp_token', 'vp_token_single'] }*/
    );

    expect(encoded).toBe(
      `presentation_submission=%7B%22id%22%3A%22bbYJTQe7YPvVx-3rLl4Aq%22%2C%22definition_id%22%3A%22000fc41b-2859-4fc3-b797-510492a9479a%22%2C%22descriptor_map%22%3A%5B%7B%22id%22%3A%22OpenBadgeCredential%22%2C%22format%22%3A%22jwt_vp%22%2C%22path%22%3A%22%24%22%2C%22path_nested%22%3A%7B%22id%22%3A%22OpenBadgeCredential%22%2C%22format%22%3A%22jwt_vc_json%22%2C%22path%22%3A%22%24.vp.verifiableCredential%5B0%5D%22%7D%7D%5D%7D&vp_token=%5B%22ey...1%22%2C%22ey...2%22%5D&vp_token_single=ey...3`,
    );
  });
});
