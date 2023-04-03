import { CredentialOfferPayloadV1_0_11 } from './v1_0_11.types';

export interface IssuerState {
  credentialOffer: CredentialOfferPayloadV1_0_11;
  createdOn: number;
}

export interface IIssuerStateManager {
  setState(issuerState: string, payload: IssuerState): Map<string, IssuerState>;

  getState(issuerState: string): IssuerState | undefined;

  hasState(issuerState: string): boolean;

  deleteState(issuerState: string): boolean;

  clearExpiredStates(timestamp?: number): void; // clears all expired states compared against timestamp if provided, otherwise current timestamp

  clearAllStates(): void; // clears all states
}
