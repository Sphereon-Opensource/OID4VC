import { extendContextLoader } from '@digitalcredentials/jsonld-signatures';
import vc from '@digitalcredentials/vc';
import fetch from 'cross-fetch';

export class DocumentLoader {
  getLoader() {
    return extendContextLoader(async (url: string) => {
      if (url === 'https://identity.foundation/.well-known/did-configuration/v1') {
        // Not sure what is happening, but this URL is failing in Github. Probably, cloudflare getting in the way, which might have impact in production settings to
        return {
          document: {
            documentUrl: url,
            '@context': [
              {
                '@version': 1.1,
                '@protected': true,
                LinkedDomains: 'https://identity.foundation/.well-known/resources/did-configuration/#LinkedDomains',
                DomainLinkageCredential: 'https://identity.foundation/.well-known/resources/did-configuration/#DomainLinkageCredential',
                origin: 'https://identity.foundation/.well-known/resources/did-configuration/#origin',
                linked_dids: 'https://identity.foundation/.well-known/resources/did-configuration/#linked_dids',
              },
            ],
          },
        };
      }
      try {
        const response = await fetch(url);
        if (response.status >= 200 && response.status < 300) {
          const document = await response.json();
          return {
            contextUrl: null,
            documentUrl: url,
            document,
          };
        } else {
          console.log(`ERROR: ${url}`);
          console.log(`url: ${url}, status: ${response.status}: ${response.statusText}`);
          console.log(`response: ${await response.text()}`);
        }
      } catch (error) {
        console.log(`ERROR:::::::: ${url}: ${JSON.stringify(error.message)}`);
      }

      const { nodeDocumentLoader } = vc;
      return nodeDocumentLoader(url);
    });
  }
}
