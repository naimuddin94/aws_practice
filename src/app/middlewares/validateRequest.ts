import { NextFunction, Request, Response } from 'express';
import { AnyZodObject } from 'zod';
import { asyncHandler } from '../utils';

export const validateRequest = (schema: AnyZodObject) => {
  return asyncHandler(
    async (req: Request, res: Response, next: NextFunction) => {
      await schema.parseAsync({
        body: req.body,
        cookies: req.cookies,
      });

      next();
    }
  );
};

export const validateRequestCookies = (schema: AnyZodObject) => {
  return asyncHandler(
    async (req: Request, res: Response, next: NextFunction) => {
      const parsedCookies = await schema.parseAsync({
        cookies: req.cookies,
      });

      req.cookies = parsedCookies.cookies;

      next();
    }
  );
};

export const validateRequestFromFormData = (schema: AnyZodObject) => {
  return asyncHandler(
    async (req: Request, res: Response, next: NextFunction) => {
      if (req?.body?.data) {
        await schema.parseAsync({
          body: JSON.parse(req.body.data),
          cookies: req.cookies,
        });

        req.body = JSON.parse(req.body.data);

        next();
      }
    }
  );
};
