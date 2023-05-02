export const getNumberOrUndefined = (input?: string): number | undefined => {
  return input && !isNaN(+input) ? +input : undefined;
};
