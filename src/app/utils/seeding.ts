import config from '../config';
import { ROLE } from '../modules/Auth/auth.constant';
import Auth from '../modules/Auth/auth.model';

const seedingAdmin = async () => {
  try {
    // at first check if the admin exist of not
    const admin = await Auth.findOne({
      role: ROLE.SUPER_ADMIN,
      email: config.super_admin.email,
    });
    if (!admin) {
      await Auth.create({
        fullName: 'Super Admin',
        role: ROLE.SUPER_ADMIN,
        email: config.super_admin.email,
        password: config.super_admin.password,
        image: config.super_admin.profile_photo,
        isVerified: true,
      });
    }
  } catch {
    console.log('Error seeding super admin');
  }
};

export default seedingAdmin;
