import nock from 'nock'

import { post } from '..'

const URL = 'https://example.com'
nock(URL)
  .post('/404', { iss: 'mock' }, { reqheaders: { Authorization: 'Bearer bearerToken' } })
  .reply(404, 'Not found')
nock(URL)
  .post('/200', { iss: 'mock' }, { reqheaders: { Authorization: 'Bearer bearerToken' } })
  .reply(200, '{"status": "ok"}')
nock(URL)
  .post('/201', { iss: 'mock' }, { reqheaders: { Authorization: 'Bearer bearerToken' } })
  .reply(201, '{"status": "ok"}')

describe('HttpUtils should', () => {
  it('have an error body when response is not 200 or 201', async () => {
    expect.assertions(1)
    await expect(
      post(`${URL}/404`, JSON.stringify({ iss: 'mock' }), { bearerToken: 'bearerToken' }).then((value) => value.errorBody),
    ).resolves.toMatch('Not found')
  })

  it('return response when response HTTP status is 200', async () => {
    expect.assertions(1)
    await expect(
      post(`${URL}/200`, JSON.stringify({ iss: 'mock' }), { bearerToken: 'bearerToken' }).then((value) => value.successBody),
    ).resolves.toMatchObject({
      status: 'ok',
    })
  })
  it('return response when response HTTP status is 201', async () => {
    expect.assertions(1)
    await expect(
      post(`${URL}/201`, JSON.stringify({ iss: 'mock' }), { bearerToken: 'bearerToken' }).then((value) => value.successBody),
    ).resolves.toMatchObject({
      status: 'ok',
    })
  })
})
