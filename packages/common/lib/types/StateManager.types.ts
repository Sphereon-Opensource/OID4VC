import { CredentialOfferPayloadV1_0_11 } from './v1_0_11.types';

export interface CredentialOfferState {
  clientId?: string;
  credentialOffer: CredentialOfferPayloadV1_0_11;
  createdOn: number;
  preAuthorizedCodeExpiresIn: number;
  userPin: number;
}

export interface CNonceState {
  cNonce: string;
  createdOn: number;
}

export interface IStateManager<T> {
  setState(state: string, payload: T): Promise<void>;

  getState(state: string): Promise<T | undefined>;

  hasState(state: string): Promise<boolean>;

  deleteState(state: string): Promise<boolean>;

  clearExpiredStates(timestamp?: number): Promise<void>; // clears all expired states compared against timestamp if provided, otherwise current timestamp

  clearAllStates(): Promise<void>; // clears all states

  getAssertedState(issuerState: string): Promise<T>;
}
