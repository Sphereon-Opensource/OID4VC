import { CommonAuthorizationDetails, CredentialFormatEnum } from '@sphereon/openid4vci-common';

export class AuthorizationDetailsBuilder {
  private readonly authorizationDetails: Partial<CommonAuthorizationDetails>;

  constructor() {
    this.authorizationDetails = {};
  }

  withType(type: string): AuthorizationDetailsBuilder {
    this.authorizationDetails.type = type;
    return this;
  }

  withFormats(format: CredentialFormatEnum): AuthorizationDetailsBuilder {
    this.authorizationDetails.format = format;
    return this;
  }

  withLocations(locations: string[]): AuthorizationDetailsBuilder {
    if (this.authorizationDetails.locations) {
      this.authorizationDetails.locations.push(...locations);
    } else {
      this.authorizationDetails.locations = locations;
    }
    return this;
  }

  addLocation(location: string): AuthorizationDetailsBuilder {
    if (this.authorizationDetails.locations) {
      this.authorizationDetails.locations.push(location);
    } else {
      this.authorizationDetails.locations = [location];
    }
    return this;
  }

  build(): CommonAuthorizationDetails {
    if (this.authorizationDetails.format && this.authorizationDetails.type) {
      return this.authorizationDetails as CommonAuthorizationDetails;
    }
    throw new Error('Type and format are required properties');
  }
}
