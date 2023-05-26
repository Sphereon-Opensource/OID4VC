import { CredentialOfferV1_0_11 } from './v1_0_11.types';

export interface StateType {
  createdAt: number;
}

export interface CredentialOfferSession extends StateType {
  clientId?: string;
  credentialOffer: CredentialOfferV1_0_11;
  userPin?: string;
  issuerState?: string; //todo: Probably good to hash it here, since it would come in from the client and we could match the hash and thus use the client value
  preAuthorizedCode?: string; //todo: Probably good to hash it here, since it would come in from the client and we could match the hash and thus use the client value
}

export interface CNonceState extends StateType {
  cNonce: string;
  issuerState?: string;
  preAuthorizedCode?: string; //todo: Probably good to hash it here, since it would come in from the client and we could match the hash and thus use the client value
}

export interface URIState extends StateType {
  issuerState?: string; //todo: Probably good to hash it here, since it would come in from the client and we could match the hash and thus use the client value
  preAuthorizedCode?: string; //todo: Probably good to hash it here, since it would come in from the client and we could match the hash and thus use the client value
  uri: string; //todo: Probably good to hash it here, since it would come in from the client and we could match the hash and thus use the client value
}

export interface IStateManager<T extends StateType> {
  set(id: string, stateValue: T): Promise<void>;

  get(id: string): Promise<T | undefined>;

  has(id: string): Promise<boolean>;

  delete(id: string): Promise<boolean>;

  clearExpired(timestamp?: number): Promise<void>; // clears all expired states compared against timestamp if provided, otherwise current timestamp

  clearAll(): Promise<void>; // clears all states

  getAsserted(id: string): Promise<T>;

  startCleanupRoutine(timeout?: number): Promise<void>;

  stopCleanupRoutine(): Promise<void>;
}
