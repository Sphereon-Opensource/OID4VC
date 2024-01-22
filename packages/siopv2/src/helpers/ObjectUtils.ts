import { JSONPath as jp } from '@astronautlabs/jsonpath';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function extractDataFromPath(obj: unknown, path: string): { path: string[]; value: any }[] {
  return jp.nodes(obj, path);
}

export function isStringNullOrEmpty(key: string) {
  return !key || !key.length;
}

export function removeNullUndefined<T>(data: unknown): T {
  if (!data) {
    return data as T;
  }
  //transform properties into key-values pairs and filter all the empty-values
  const entries = Object.entries(data).filter(([, value]) => value != null);
  //map through all the remaining properties and check if the value is an object.
  //if value is object, use recursion to remove empty properties
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  const clean = entries.map(([key, v]) => {
    const value = typeof v === 'object' && !Array.isArray(v) ? removeNullUndefined(v) : v;
    return [key, value];
  });
  //transform the key-value pairs back to an object.
  return Object.fromEntries(clean) as T;
}
