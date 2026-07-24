type Result<T, E extends Error> = { ok: true; value: T } | { ok: false; error: E };

export const toResult = async <T, E extends Error>(promise: Promise<T>): Promise<Result<T, E>> => {
  try {
    const value = await promise;
    return { ok: true, value };
  } catch (error) {
    return { ok: false, error: error as E };
  }
};
