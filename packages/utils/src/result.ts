type Result<T, E extends Error> = { ok: true; value: T } | { ok: false; error: E };

export function toResult<T, E extends Error>(value: PromiseLike<T>): Promise<Result<T, E>>;
export function toResult<T, E extends Error>(value: T): Promise<Result<T, E>>;
export async function toResult<T, E extends Error>(value: T | PromiseLike<T>): Promise<Result<T, E>> {
  try {
    const result = await value;
    return { ok: true, value: result };
  } catch (error) {
    return { ok: false, error: error as E };
  }
}
