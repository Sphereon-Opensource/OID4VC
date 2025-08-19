import {ClientIdentifierPrefix} from '../types';

const clientIdentifierPrefixes = Object.values(ClientIdentifierPrefix)

export const getClientIdentifierPrefix = (clientId: string): string | null => {
    const regex = new RegExp(`^(${clientIdentifierPrefixes.join('|')})[:_-]`)
    const match = clientId.match(regex)
    return match ? match[1] : null
}

export const removeClientIdentifierPrefix = (clientId: string): string => {
    const regex = new RegExp(`^(${clientIdentifierPrefixes.join('|')})[:_-]`)
    return clientId.replace(regex, '')
}
