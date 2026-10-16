import { ValidationError } from '../../errors.js';

/**
 * Validates request parts against Zod schemas and replaces them with the parsed
 * result, so handlers work with coerced, stripped, trusted data.
 *
 *   router.post('/x', validate({ body: createXSchema }), handler)
 *
 * Note it assigns to `req.validated` rather than mutating `req.query`, which is
 * a getter in Express 5 and cannot be reassigned.
 */
export function validate(schemas) {
  return (req, _res, next) => {
    const validated = {};
    const issues = [];

    for (const part of ['body', 'query', 'params']) {
      const schema = schemas[part];
      if (!schema) continue;

      const result = schema.safeParse(req[part]);
      if (result.success) {
        validated[part] = result.data;
      } else {
        for (const issue of result.error.issues) {
          issues.push({
            field: [part, ...issue.path].join('.'),
            code: issue.code,
            message: issue.message,
          });
        }
      }
    }

    // Report every failing field at once. Returning one error at a time makes
    // callers play whack-a-mole against the API.
    if (issues.length > 0) return next(new ValidationError(issues));

    req.validated = validated;
    if (validated.body) req.body = validated.body;
    return next();
  };
}
