import { EndpointMetadata } from "./types";


export type CodeChallengeMethod = 'text' | 'S256';


export class AuthorizationRequestClientBuilder {

    authorizationEndpoint: string;
    clientId: string;
    codeChallange: string;
    codeChallengeMethod: CodeChallengeMethod;
    authorizationDetails: Record<string, unknown> // TODO: add typing for this
    redirectUri?: string;

    public static fromMetadata(metadata: EndpointMetadata) {
        const builder = new AuthorizationRequestClientBuilder();
        builder.withAuthorizationEndpointFromMetadata(metadata);

    }

    public withAuthorizationEndpointFromMetadata(metadata: EndpointMetadata): AuthorizationRequestClientBuilder {
        this.authorizationEndpoint = metadata.authorization_endpoint;
        return this;
    }

    public withClientId(clientId: string): AuthorizationRequestClientBuilder {
        this.clientId = clientId;
        return this;
    }

    public withCodeChallenge(codeChallenge: string): AuthorizationRequestClientBuilder {
        this.codeChallange = codeChallenge;
        return this;
    }

    public withCodeChallengeMethod(codeChallengeMethod: CodeChallengeMethod): AuthorizationRequestClientBuilder {
        this.codeChallengeMethod = codeChallengeMethod;
        return this;
    }

    public withAuthorizationDetails(authorizationDetails: Record<string, unknown>): AuthorizationRequestClientBuilder {
        this.authorizationDetails = authorizationDetails;
        return this;
    }

    public withRedirectUri(redirectUri: string): AuthorizationRequestClientBuilder {
        this.redirectUri = redirectUri;
        return this;
    }

}
