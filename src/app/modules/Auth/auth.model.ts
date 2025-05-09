/* eslint-disable @typescript-eslint/no-explicit-any */
import mongoose from 'mongoose';
import { IAuth, IAuthModel } from './auth.interface';
import { ROLE } from './auth.constant';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import config from '../../config';

const authSchema = new mongoose.Schema<IAuth, IAuthModel>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
    },
    fullName: {
      type: String,
      required: false,
    },
    image: {
      type: String,
      required: false,
    },
    phoneNumber: {
      type: String,
      required: false,
    },
    password: {
      type: String,
      required: false,
      select: 0,
    },
    fcmToken: {
      type: String,
      required: false,
      default: null,
    },
    role: {
      type: String,
      enum: Object.values(ROLE),
      default: ROLE.BUYER,
    },
    isSocialLogin: {
      type: Boolean,
      default: false,
    },
    refreshToken: {
      type: String,
      default: null,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true, versionKey: false }
);

// Custom hooks/methods

// Modified password fields before save to database
authSchema.pre('save', async function (next) {
  try {
    // Check if the password is modified or this is a new user
    if (this.password && (this.isModified('password') || this.isNew)) {
      const hashPassword = await bcrypt.hash(
        this.password,
        Number(config.bcrypt_salt_rounds)
      );
      this.password = hashPassword;
    }
    next();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (error: any) {
    next(error);
  }
});

// For generating access token
authSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      id: this._id,
      email: this.email,
      role: this.role,
    },
    config.jwt_access_secret!,
    {
      expiresIn: config.jwt_access_expires_in as any,
    }
  );
};

// For generating refresh token
authSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      id: this._id,
    },
    config.jwt_refresh_secret!,
    {
      expiresIn: config.jwt_refresh_expires_in as any,
    }
  );
};

// For check the password is correct
authSchema.methods.isPasswordCorrect = async function (password: string) {
  return await bcrypt.compare(password, this.password);
};

const Auth = mongoose.model<IAuth, IAuthModel>('Auth', authSchema);

export default Auth;
