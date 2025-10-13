// Centralized constants and types for auth and user domain

// Roles
export const AvailableUserRoles = ["ADMIN", "USER"] as const;
export type UserRole = (typeof AvailableUserRoles)[number];
export enum UserRolesEnum {
  ADMIN = "ADMIN",
  USER = "USER",
}

// Login types (local + social providers)
export const AvailableSocialLogins = [
  "EMAIL_PASSWORD",
  "GOOGLE",
  "GITHUB",
] as const;
export type SocialLoginType = (typeof AvailableSocialLogins)[number];
export enum UserLoginType {
  EMAIL_PASSWORD = "EMAIL_PASSWORD",
  GOOGLE = "GOOGLE",
  GITHUB = "GITHUB",
}

// Temporary token expiry (e.g., email verification / password reset)
// Default: 20 minutes
export const USER_TEMPORARY_TOKEN_EXPIRY = 20 * 60 * 1000; // in ms
