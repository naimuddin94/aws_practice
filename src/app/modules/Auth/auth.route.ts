import { Router } from 'express';
import { auth, validateRequest } from '../../middlewares';
import { AuthValidation } from './auth.validation';
import { AuthController } from './auth.controller';
import { upload } from '../../lib';

const router = Router();

router
  .route('/signup')
  .post(
    validateRequest(AuthValidation.createSchema),
    AuthController.createAuth
  );

router
  .route('/signin')
  .post(validateRequest(AuthValidation.signinSchema), AuthController.signin);

router.route('/verify-signup-otp').post(AuthController.saveAuthData);

router
  .route('/verify-signup-otp-again')
  .post(AuthController.signupOtpSendAgain);

router
  .route('/social-signin')
  .post(
    validateRequest(AuthValidation.socialSchema),
    AuthController.socialSignin
  );

router
  .route('/change-password')
  .patch(
    auth(),
    validateRequest(AuthValidation.passwordChangeSchema),
    AuthController.changePassword
  );

// For forget password
router
  .route('/forget-password')
  .post(
    validateRequest(AuthValidation.forgetPasswordSchema),
    AuthController.forgetPassword
  );

router
  .route('/forget-password-verify')
  .post(
    validateRequest(AuthValidation.forgetPasswordVerifySchema),
    AuthController.verifyOtpForForgetPassword
  );

router
  .route('/reset-password')
  .post(
    validateRequest(AuthValidation.resetPasswordSchema),
    AuthController.resetPassword
  );

router
  .route('/profile-image')
  .put(auth(), upload.single('file'), AuthController.updateProfilePhoto);

export const AuthRoutes = router;
