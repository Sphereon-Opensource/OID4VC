export type IBuilder<T> = {
  [k in keyof T]-?: (arg: T[k]) => IBuilder<T>;
} & {
  build(): T;
};

export function Builder<T>(): IBuilder<T> {
  const built: Record<string, unknown> = {};

  const builder = new Proxy(
    {},
    {
      get(_target: unknown, prop: string | symbol) {
        if ('build' === prop) {
          return () => built;
        }

        return (x: unknown): unknown => {
          built[prop.toString()] = x;
          return builder;
        };
      },
    }
  );

  return builder as IBuilder<T>;
}
