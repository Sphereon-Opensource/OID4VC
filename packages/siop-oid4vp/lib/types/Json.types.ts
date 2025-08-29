export type Json =
    | string
    | number
    | boolean
    | null
    | {
    // Not exported from dcql
    [key: string]: Json
}
    | Json[]
