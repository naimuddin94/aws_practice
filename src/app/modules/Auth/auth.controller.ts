import status from 'http-status';
import { AppResponse, asyncHandler, options } from '../../utils';
import { AuthService } from './auth.service';
import { CookieOptions } from 'express';

const createAuth = asyncHandler(async (req, res) => {
  const result = await AuthService.createAuth(req.body);

  res
    .status(status.OK)
    .json(new AppResponse(status.OK, result, 'OTP send successfully'));
});

const signupOtpSendAgain = asyncHandler(async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1] || '';
  const result = await AuthService.signupOtpSendAgain(token);

  res
    .status(status.OK)
    .json(new AppResponse(status.OK, result, 'OTP send again successfully'));
});

const saveAuthData = asyncHandler(async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1] || '';
  const otp = req.body.otp;
  const result = await AuthService.saveAuthIntoDB(token, otp);

  res
    .status(status.CREATED)
    .cookie('accessToken', result.accessToken, options as CookieOptions)
    .cookie('refreshToken', result.refreshToken, options as CookieOptions)
    .json(
      new AppResponse(
        status.CREATED,
        { accessToken: result.accessToken },
        'Account created successfully'
      )
    );
});

const signin = asyncHandler(async (req, res) => {
  const result = await AuthService.signinIntoDB(req.body);

  res
    .status(status.OK)
    .cookie('accessToken', result.accessToken, options as CookieOptions)
    .cookie('refreshToken', result.refreshToken, options as CookieOptions)
    .json(new AppResponse(status.OK, result, 'Signin successfully'));
});

const socialSignin = asyncHandler(async (req, res) => {
  const { response, accessToken, refreshToken } =
    await AuthService.socialLoginServices(req.body);

  res
    .status(status.OK)
    .cookie('accessToken', accessToken, options as CookieOptions)
    .cookie('refreshToken', refreshToken, options as CookieOptions)
    .json(new AppResponse(status.OK, response, 'Signin successfully'));
});

const updateProfilePhoto = asyncHandler(async (req, res) => {
  const result = await AuthService.updateProfilePhoto(req.user, req.file);

  res
    .status(status.OK)
    .json(
      new AppResponse(status.OK, result, 'Profile photo update successfully')
    );
});

const changePassword = asyncHandler(async (req, res) => {
  const accessToken = req.cookies.accessToken;
  const result = await AuthService.changePasswordIntoDB(accessToken, req.body);

  res
    .status(status.OK)
    .json(new AppResponse(status.OK, result, 'Password change successfully'));
});

// For forget password
const forgetPassword = asyncHandler(async (req, res) => {
  const email = req.body.email;
  const result = await AuthService.forgotPassword(email);

  res
    .status(status.OK)
    .json(
      new AppResponse(
        status.OK,
        result,
        'Your OTP has been successfully sent to your email.'
      )
    );
});

const verifyOtpForForgetPassword = asyncHandler(async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1] || '';
  const otp = req.body.otp;
  const result = await AuthService.verifyOtpForForgetPassword(token, otp);

  res
    .status(status.OK)
    .json(new AppResponse(status.OK, result, 'OTP verified successfully'));
});

const resetPassword = asyncHandler(async (req, res) => {
  const resetPasswordToken =
    req.header('Authorization')?.replace('Bearer ', '') ||
    req.cookies?.resetPasswordToken;
  const result = await AuthService.resetPasswordIntoDB(
    resetPasswordToken,
    req.body.newPassword
  );

  res
    .status(status.OK)
    .json(new AppResponse(status.OK, result, 'Reset password successfully'));
});

export const AuthController = {
  createAuth,
  saveAuthData,
  signupOtpSendAgain,
  signin,
  socialSignin,
  updateProfilePhoto,
  changePassword,
  forgetPassword,
  verifyOtpForForgetPassword,
  resetPassword,
};
