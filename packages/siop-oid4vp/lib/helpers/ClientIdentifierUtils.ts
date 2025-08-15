import {ClientIdentifierPrefix} from '../types';

export const getClientIdentifierPrefix = (clientId: string): string | null => {
    const match = clientId.match(/^([a-zA-Z0-9_-]+)[:_-]/)
    return match ? match[1] : null
}

export const removeClientIdentifierPrefix = (clientId: string): string => {
    const prefixes = Object.values(ClientIdentifierPrefix)
    const regex = new RegExp(`^(${prefixes.join('|')})[:_-]`)
    return clientId.replace(regex, '')
}
