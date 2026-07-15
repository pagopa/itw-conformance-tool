import { z } from 'zod';

export const toFastifyJsonSchema = <S extends z.ZodType>(schema: S) => {
  return schema.toJSONSchema({ target: 'draft-07' });
};
