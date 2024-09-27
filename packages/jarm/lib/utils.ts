export function appendQueryParams(input: { url: URL; params: Record<string, string | number | boolean> }) {
  const { url, params } = input;

  // Append the new query parameters from the params object
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.append(key, encodeURIComponent(value));
  }

  return url;
}

export function appendFragmentParams(input: { url: URL; fragments: Record<string, string | number | boolean> }) {
  const { url, fragments } = input;

  // Convert existing fragment to an object and remove the leading '#'
  const fragmentParams = new URLSearchParams(url.hash.slice(1)); // Remove the leading '#' from the fragment

  // Append the new fragments from the fragments object
  for (const [key, value] of Object.entries(fragments)) {
    fragmentParams.append(key, encodeURIComponent(value));
  }

  // Rebuild the fragment string and assign it to the URL
  url.hash = fragmentParams.toString();

  return url;
}
