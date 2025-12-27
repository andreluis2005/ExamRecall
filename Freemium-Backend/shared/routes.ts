import { z } from 'zod';
import { insertUserSchema, loginSchema, users, type InsertUser, type LoginRequest } from './schema';

export { insertUserSchema, loginSchema, type InsertUser, type LoginRequest };
export const registerSchema = insertUserSchema;

export const errorSchemas = {
  validation: z.object({
    message: z.string(),
  }),
  unauthorized: z.object({
    message: z.string(),
  }),
  conflict: z.object({
    message: z.string(),
  }),
};

export const api = {
  auth: {
    register: {
      method: 'POST' as const,
      path: '/api/auth/register',
      input: insertUserSchema,
      responses: {
        201: z.object({
          token: z.string(),
          user: z.custom<typeof users.$inferSelect>(),
        }),
        400: errorSchemas.validation,
        409: errorSchemas.conflict,
      },
    },
    login: {
      method: 'POST' as const,
      path: '/api/auth/login',
      input: loginSchema,
      responses: {
        200: z.object({
          token: z.string(),
          user: z.custom<typeof users.$inferSelect>(),
        }),
        401: errorSchemas.unauthorized,
      },
    },
  },
  user: {
    profile: {
      method: 'GET' as const,
      path: '/api/user/profile',
      responses: {
        200: z.custom<typeof users.$inferSelect>(),
        401: errorSchemas.unauthorized,
      },
    },
  },
};

export function buildUrl(path: string, params?: Record<string, string | number>): string {
  let url = path;
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (url.includes(`:${key}`)) {
        url = url.replace(`:${key}`, String(value));
      }
    });
  }
  return url;
}
