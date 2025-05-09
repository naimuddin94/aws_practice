/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable no-unused-vars */
import { Document, Model } from 'mongoose';
import { TProvider, TRole } from './auth.constant';

export interface IAuth extends Document {
  createdAt: any;
  email: string;
  fullName?: string;
  phoneNumber: string;
  password?: string;
  address?: string;
  fcmToken?: string | null;
  provider?: TProvider;
  image?: string;
  role: TRole;
  isSocialLogin: boolean;
  refreshToken?: string | null;                                                                           
  isVerified: boolean;
  isActive: boolean;
}

export interface IAuthMethods {
  isPasswordCorrect(password: string): Promise<boolean>;
  generateAccessToken(): string;
  generateRefreshToken(): string;
}

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface IAuthModel
  extends Model<IAuth, Record<string, never>, IAuthMethods> {}
