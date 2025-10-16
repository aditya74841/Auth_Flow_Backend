import mongoose, { Document, Model, Schema } from "mongoose";
import jwt, { SignOptions } from "jsonwebtoken";
import bcrypt from "bcrypt";
import crypto from "crypto";
import {
  AvailableSocialLogins,
  AvailableUserRoles,
  USER_TEMPORARY_TOKEN_EXPIRY,
  UserLoginType,
  UserRolesEnum,
} from "../constants";

// Core user shape stored in DB
interface IUser {
  name?: string;
  email: string;
  username?: string;
  phoneNumber?: string;
  password?: string; // hashed in DB (optional for social logins)
  companyId?: mongoose.Types.ObjectId | null;
  role: UserRolesEnum;
  loginType: UserLoginType;
  avatar?: {
    url?: string;
    localPath?: string;
  };
  isEmailVerified: boolean;
  // Sensitive one-time values (not recommended to keep on user long-term)
  forgotPasswordToken?: string;
  forgotPasswordExpiry?: Date;
  emailVerificationToken?: string;
  emailVerificationExpiry?: Date | number;
}

// Instance methods available on User documents
interface IUserMethods {
  generateAccessToken(ttlOverride?: string): string;
  generateRefreshToken(ttlOverride?: string): string;
  generateTemporaryToken(): {
    unHashedToken: string;
    hashedToken: string;
    tokenExpiry: number; // ms timestamp
  };
  comparePassword(candidate: string): Promise<boolean>;
}

// Document type that includes mongoose properties and our methods
interface IUserDocument extends IUser, Document, IUserMethods {
  _id: mongoose.Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

// Model type for potential statics in future
interface IUserModel extends Model<IUserDocument, {}, IUserMethods> {}

const userSchema = new Schema<IUserDocument, IUserModel, IUserMethods>(
  {
    name: {
      type: String,
      trim: true,
      minlength: [2, "Name must be at least 2 characters"],
      maxlength: [100, "Name cannot exceed 100 characters"],
      default: "",
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      trim: true,
      // index: true,
      match: [
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        "Please provide a valid email address",
      ],
    },
    username: {
      type: String,
      lowercase: true,
      trim: true,
      // unique: true will be enforced via a partial index below
    },
    phoneNumber: {
      type: String,
      trim: true,
    },
    password: {
      type: String,
      // Required only for email/password login
      required: [true, "Password is required"],
      minlength: [6, "Password must be at least 6 characters"],
      select: false, // never fetch by default
    },
    // companyId: {
    //   type: Schema.Types.ObjectId,
    //   ref: "Company",
    //   default: null,
    // },
    role: {
      type: String,
      enum: AvailableUserRoles,
      default: UserRolesEnum.USER,
      required: true,
    },
    loginType: {
      type: String,
      enum: AvailableSocialLogins,
      default: UserLoginType.EMAIL_PASSWORD,
      required: true,
    },
    avatar: {
      type: {
        url: {
          type: String,
          default: "https://via.placeholder.com/200x200.png",
        },
        localPath: { type: String, default: "" },
      },
      default: undefined,
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },

    // The following token fields are sensitive. Prefer dedicated collections.
    forgotPasswordToken: { type: String, select: false },
    forgotPasswordExpiry: { type: Date, select: false },
    emailVerificationToken: { type: String, select: false },
    emailVerificationExpiry: { type: Date, select: false },
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform: (_doc: any, ret: any) => {
        const sanitized: any = { ...ret };
        sanitized.id = sanitized._id;
        delete sanitized._id;
        delete sanitized.password; // never expose password hash
        delete sanitized.__v;
        return sanitized;
      },
    },
    toObject: {
      virtuals: true,
      transform: (_doc: any, ret: any) => {
        const sanitized: any = { ...ret };
        sanitized.id = sanitized._id;
        delete sanitized._id;
        delete sanitized.password;
        delete sanitized.__v;
        return sanitized;
      },
    },
  }
);

// Indexes
userSchema.index({ email: 1 });
// Partial unique index for username only when present (non-null/non-empty)
userSchema.index(
  { username: 1 },
  { unique: true, partialFilterExpression: { username: { $type: "string" } } }
);

// Helper to detect if a string looks like a bcrypt hash (to avoid double-hashing)
function looksLikeBcryptHash(value: string): boolean {
  return /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(value);
}

// Pre-save hook: hash password if modified and present
userSchema.pre("save", async function (next) {
  const user = this as IUserDocument;

  // Only process password if modified
  if (!user.isModified("password") || !user.password) {
    return next();
  }

  if (user.loginType === UserLoginType.EMAIL_PASSWORD && !user.password) {
    return next(new Error("Password is required for email/password login"));
  }

  if (looksLikeBcryptHash(user.password)) return next();

  const rounds = Number(process.env.BCRYPT_SALT_ROUNDS || 12);
  user.password = await bcrypt.hash(user.password, rounds);

  next();
});

userSchema.methods.comparePassword = async function (
  candidate: string
): Promise<boolean> {
  if (!this.password) return false;
  return bcrypt.compare(candidate, this.password);
};

userSchema.methods.generateAccessToken = function (
  ttlOverride?: string
): string {
  const user = this as IUserDocument;
  const secret = process.env.ACCESS_TOKEN_SECRET as string | undefined;
  if (!secret) throw new Error("ACCESS_TOKEN_SECRET is not defined");

  const expiresIn: SignOptions["expiresIn"] =
    (ttlOverride as any) || (process.env.ACCESS_TOKEN_TTL as any) || "15m";

  const payload = {
    sub: user._id.toString(),
    email: user.email,
    role: user.role,
  } as const;

  return jwt.sign(payload, secret, { expiresIn });
};

userSchema.methods.generateRefreshToken = function (
  ttlOverride?: string
): string {
  const user = this as IUserDocument;
  const secret = process.env.REFRESH_TOKEN_SECRET as string | undefined;
  if (!secret) throw new Error("REFRESH_TOKEN_SECRET is not defined");

  const expiresIn: SignOptions["expiresIn"] =
    (ttlOverride as any) || (process.env.REFRESH_TOKEN_TTL as any) || "10d";

  const payload = { sub: user._id.toString() } as const;
  return jwt.sign(payload, secret, { expiresIn });
};

userSchema.methods.generateTemporaryToken = function () {
  const unHashedToken = crypto.randomBytes(20).toString("hex");
  const hashedToken = crypto
    .createHash("sha256")
    .update(unHashedToken)
    .digest("hex");
  const tokenExpiry = Date.now() + USER_TEMPORARY_TOKEN_EXPIRY; // ms timestamp

  return { unHashedToken, hashedToken, tokenExpiry };
};

export const User: Model<IUserDocument> = mongoose.model<
  IUserDocument,
  IUserModel
>("User", userSchema);

export type { IUser, IUserDocument, IUserMethods, IUserModel };
