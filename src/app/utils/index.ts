import { Logger } from './logger';
import AppError from './AppError';
import AppResponse from './AppResponse';
import asyncHandler from './asyncHandler';
import { deleteFile } from './deleteFile';
import globalErrorHandler from './globalErrorHandler';
import notFound from './notFound';
import sendContactUsEmail from './sendContactUsEmail';
import sendOtpEmail from './sendOtpEmail';

// JWT configuration
const options = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
  maxAge: 365 * 24 * 60 * 60 * 1000,
};

export {
  AppError,
  AppResponse,
  asyncHandler,
  globalErrorHandler,
  notFound,
  options,
  sendOtpEmail,
  deleteFile,
  sendContactUsEmail,
  Logger
};
