export const ROLE = {
  BUYER: 'BUYER',
  SELLER: 'SELLER',
  ADMIN: 'ADMIN',
  SUPER_ADMIN: 'SUPER_ADMIN',
} as const;

export type TRole = keyof typeof ROLE;

export const PROVIDER = {
  GOOGLE: 'GOOGLE',
  FACEBOOK: 'FACEBOOK',
} as const;

export type TProvider = keyof typeof PROVIDER;

export type ValueOf<T> = T[keyof T];
