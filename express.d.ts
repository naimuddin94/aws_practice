import { IAuth } from './src/app/modules/Auth/auth.interface';

declare global {
  namespace Express {
    interface Request {
      user: IAuth;
    }
  }
}
