import { PEX } from '@sphereon/pex';

import { anyDef, VCs } from './fixtures';

describe('auth0 presentation tool', () => {
  it('any match definition should return all credentials', async () => {
    const pex = new PEX();
    expect(VCs).toHaveLength(5);
    const selectResult = await pex.selectFrom(anyDef, VCs);
    expect(selectResult.matches).toHaveLength(5);
  });
});
