type Result<T, E extends Error> = { ok: true; value: T } | { ok: false; error: E };

export const toResult = async <T, E extends Error>(value: T | PromiseLike<T>): Promise<Result<T, E>> => {
  try {
    const result = await value;
    return { ok: true, value: result };
  } catch (error) {
    return { ok: false, error: error as E };
  }
};
