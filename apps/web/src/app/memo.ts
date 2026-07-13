/** Last-call memoization — derived data recomputes only when inputs change. */
export function memoLast<A extends unknown[], R>(fn: (...args: A) => R): (...args: A) => R {
  let last: { args: A; result: R } | null = null;
  return (...args: A) => {
    if (last && last.args.length === args.length && last.args.every((v, i) => Object.is(v, args[i]))) {
      return last.result;
    }
    const result = fn(...args);
    last = { args, result };
    return result;
  };
}
