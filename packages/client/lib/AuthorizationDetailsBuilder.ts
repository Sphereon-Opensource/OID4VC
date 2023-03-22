import { AuthorizationDetails } from '@sphereon/openid4vci-common';
import { CredentialFormat } from '@sphereon/ssi-types';

export class AuthorizationDetailsBuilder {
  private authorizationDetails: Partial<AuthorizationDetails>;

  constructor() {
    this.authorizationDetails = {};
  }

  withType(type: string): AuthorizationDetailsBuilder {
    this.authorizationDetails.type = type;
    return this;
  }

  withFormats(format: CredentialFormat | CredentialFormat[]): AuthorizationDetailsBuilder {
    if (this.authorizationDetails.format && Array.isArray(this.authorizationDetails.format)) {
      this.authorizationDetails.format.push(...format);
    } else {
      this.authorizationDetails.format = format;
    }
    return this;
  }

  withLocations(locations: string | string[]): AuthorizationDetailsBuilder {
    if (this.authorizationDetails.locations && Array.isArray(this.authorizationDetails.locations)) {
      this.authorizationDetails.locations.push(...locations);
    } else {
      this.authorizationDetails.locations = locations;
    }
    return this;
  }

  build(): AuthorizationDetails {
    if (this.authorizationDetails.format && this.authorizationDetails.type) {
      return this.authorizationDetails as AuthorizationDetails;
    }
    throw new Error('Type and format are required properties');
  }
}
