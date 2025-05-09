export interface IErrorSource {
  path: string | number;
  message: string;
}

export interface IMeta {
  page: number;
  limit: number;
  total: number;
  totalPage: number;
}

export type TProfileFileFields = {
  idFrontPart?: Express.Multer.File[];
  idBackPart?: Express.Multer.File[];
  selfieWithId?: Express.Multer.File[];
  registrationCertificate?: Express.Multer.File[];
  taxIdOrEquivalent?: Express.Multer.File[];
  studioLicense?: Express.Multer.File[];
};

export type TSocialLoginPayload = {
  email: string;
  fcmToken: string;
  image?: string;
  fullName?: string;
  phoneNumber?: string;
  address?: string;
};
