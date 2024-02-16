import { AuthorizationDetails, AuthorizationDetailsJwtVcJson, OID4VCICredentialFormat } from '@sphereon/oid4vci-common';

//todo: refactor this builder to be able to create ldp details as well
export class AuthorizationDetailsBuilder {
  private readonly authorizationDetails: Partial<Exclude<AuthorizationDetails, string>>;

  constructor() {
    this.authorizationDetails = {};
  }

  withType(type: string): AuthorizationDetailsBuilder {
    this.authorizationDetails.type = type;
    return this;
  }

  withFormats(format: OID4VCICredentialFormat): AuthorizationDetailsBuilder {
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

  //todo: we have to consider one thing, if this is a general purpose builder, we want to support ldp types here as well. and for that we need a few checks.
  buildJwtVcJson(): AuthorizationDetailsJwtVcJson {
    if (this.authorizationDetails.format && this.authorizationDetails.type) {
      return this.authorizationDetails as AuthorizationDetailsJwtVcJson;
    }
    throw new Error('Type and format are required properties');
  }
}
