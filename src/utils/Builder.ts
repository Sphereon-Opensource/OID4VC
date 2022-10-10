export type IBuilder<T> = {
  [k in keyof T]-?: (arg: T[k]) => IBuilder<T>;
} & {
  build(): T;
};

type Clazz<T> = new (...args: unknown[]) => T;

export function Builder<T>(type: Clazz<T>, template?: Partial<T>): IBuilder<T>;

export function Builder<T>(template?: Partial<T>): IBuilder<T>;

export function Builder<T>(typeOrTemplate?: Clazz<T> | Partial<T>, template?: Partial<T>): IBuilder<T> {
  let type: Clazz<T> | undefined;
  if (typeOrTemplate instanceof Function) {
    type = typeOrTemplate;
  } else {
    template = typeOrTemplate;
  }

  const built: Record<string, unknown> = template ? Object.assign({}, template) : {};

  const builder = new Proxy(
    {},
    {
      get(_target: unknown, prop: string | symbol) {
        if ('build' === prop) {
          if (type) {
            // A class name (identified by the constructor) was passed. Instantiate it with props.
            const obj: T = new type();
            return () => Object.assign(obj, { ...built });
          } else {
            // No type information - just return the object.
            return () => built;
          }
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
