import { z } from 'zod'
import {
    AuthorizationRequestStateStatus,
    AuthorizationResponseStateStatus,
    VerifiedDataMode
} from '../../types';

export const AuthorizationStatusSchema = z.enum([
    ...Object.values(AuthorizationRequestStateStatus),
    ...Object.values(AuthorizationResponseStateStatus)
]);

export const VerifiedDataModeSchema = z.enum(Object.values(VerifiedDataMode));

export const VerifiedDataOptsSchema = z.object({
    modes: z.array(VerifiedDataModeSchema).optional(),
});

export const CallbackOptsSchema = z.object({
    url: z.string(),
    verified_data: VerifiedDataOptsSchema.optional(),
    status: z.array(AuthorizationStatusSchema).optional(),
});
