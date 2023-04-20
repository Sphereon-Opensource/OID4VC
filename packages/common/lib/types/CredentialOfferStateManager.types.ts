import { CredentialOfferPayloadV1_0_11 } from './v1_0_11.types';

export interface CredentialOfferState {
  clientId: string;
  credentialOffer: CredentialOfferPayloadV1_0_11;
  createdOn: number;
}

export interface ICredentialOfferStateManager {
  setState(state: string, payload: CredentialOfferState): Promise<void>;

  getState(state: string): Promise<CredentialOfferState | undefined>;

  hasState(state: string): Promise<boolean>;

  deleteState(state: string): Promise<boolean>;

  clearExpiredStates(timestamp?: number): Promise<void>; // clears all expired states compared against timestamp if provided, otherwise current timestamp

  clearAllStates(): Promise<void>; // clears all states
}
