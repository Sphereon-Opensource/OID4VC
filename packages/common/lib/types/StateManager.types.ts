import { CredentialOfferV1_0_11 } from './v1_0_11.types';

export interface StateType {
  createdOn: number;
}
export interface CredentialOfferSession extends StateType {
  clientId?: string;
  credentialOffer: CredentialOfferV1_0_11;
  userPin?: number;
  id: string; // state or pre-authz code depending on flow
}

export interface CNonceState extends StateType {
  cNonce: string;
}

export interface URIState extends StateType {
  id: string;
  uri: string;
}

export interface IStateManager<T extends StateType> {
  set(id: string, stateValue: T): Promise<void>;

  get(id: string): Promise<T | undefined>;

  has(id: string): Promise<boolean>;

  delete(id: string): Promise<boolean>;

  clearExpired(timestamp?: number): Promise<void>; // clears all expired states compared against timestamp if provided, otherwise current timestamp

  clearAll(): Promise<void>; // clears all states

  getAsserted(id: string): Promise<T>;
}
