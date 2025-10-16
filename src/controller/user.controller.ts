import { Request, Response } from "express";
import { IUserDocument, User } from "../model/user.model";
import { asyncHandler } from "../utils/asyncHandler";
import { ApiError } from "../utils/ApiError";
import { ApiResponse } from "../utils/ApiResponse";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import {
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
  sendEmail,
} from "../utils/mail";
interface RegisterType {
  name: string;
  email: string;
  password: string;
}

interface LoginType {
  email: string;
  password: string;
}

interface ForgotPasswordBody {
  email: string;
}

interface ResetPasswordBody {
  token: string;
  newPassword: string;
}

interface VerifyEmailBody {
  token: string;
}

interface ResendVerificationBody {
  email: string;
}

interface ChangePasswordBody {
  oldPassword: string;
  newPassword: string;
}

// const registerUser = async (
//   req: Request<{}, {}, RegisterType>,
//   res: Response
// ) => {
//   try {
//     const { name, email, password } = req.body;

//     if (!name) {
//       return res.status(404).json({ message: "Name is Required" });
//     }

//     if (!email) {
//       return res.status(404).json({ message: "Email is Required" });
//     }

//     if (!password) {
//       return res.status(404).json({ message: "Password is Required" });
//     }

//     let newPassword = await bcrypt.hash(password, 10);

//     const newUser: IUserDocument = new User({
//       name,
//       email,
//       password: newPassword,
//     });

//     await newUser.save();

//     return res.status(201).json({
//       success: true,
//       message: "User registered successfully",
//     });
//   } catch (error) {
//     return res.status(500).json({
//       success: false,
//       message: "Registration failed",
//       error: error instanceof Error ? error.message : "Unknown error",
//     });
//   }
// };

const registerUser = asyncHandler(
  async (req: Request<{}, {}, RegisterType>, res: Response) => {
    const { name, password } = req.body;
    const email = req.body.email?.toLowerCase(); // Normalize email
    // Validate all required fields
    if (!name || !email || !password) {
      throw new ApiError(400, "Name, email, and password are required");
    }

    // Validate password length
    if (password.length < 6) {
      throw new ApiError(400, "Password must be at least 6 characters");
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new ApiError(400, "Please provide a valid email address");
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new ApiError(409, "User with this email already exists");
    }

    // Create new user (password hashed by model pre-save hook)
    const newUser: IUserDocument = await User.create({ name, email, password });
    const { unHashedToken, hashedToken, tokenExpiry } =
      newUser.generateTemporaryToken();

    console.log("The Temporary Token", unHashedToken, hashedToken, tokenExpiry);

    console.log(" The type of", typeof tokenExpiry);

    newUser.emailVerificationToken = hashedToken;
    newUser.emailVerificationExpiry = new Date(tokenExpiry);
    await newUser.save({ validateBeforeSave: false });
    await sendEmail({
      email: newUser?.email,
      subject: "Please verify your email",
      mailgenContent: emailVerificationMailgenContent({
        username: newUser.name,
        verificationUrl: `${req.protocol}://${req.get(
          "host"
        )}/api/v1/users/verify-email/${unHashedToken}`,
      }),
    });
    return res
      .status(201)
      .json(
        new ApiResponse(201, newUser.toJSON(), "User registered successfully")
      );
  }
);

const loginUser = asyncHandler(
  async (req: Request<{}, {}, LoginType>, res: Response) => {
    const { email, password } = req.body;
    const normalizedEmail = email?.toLowerCase();

    if (!normalizedEmail || !password) {
      throw new ApiError(400, "Email and password are required");
    }

    // Fetch user with password for verification
    const user: IUserDocument | null = await User.findOne({
      email: normalizedEmail,
    }).select("+password");

    // Use generic error to avoid user enumeration
    if (!user) {
      throw new ApiError(401, "Invalid credentials");
    }

    const valid = await user.comparePassword(password);
    if (!valid) {
      throw new ApiError(401, "Invalid credentials");
    }

    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    const isProd = process.env.NODE_ENV === "production";
    const cookieOptionsAccess = {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? ("none" as const) : ("lax" as const),
      maxAge: 1000 * 60 * 15, // 15 minutes
      path: "/",
    };
    const cookieOptionsRefresh = {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? ("none" as const) : ("lax" as const),
      maxAge: 1000 * 60 * 60 * 24 * 10, // 10 days
      path: "/",
    };

    res.cookie("accessToken", accessToken, cookieOptionsAccess);
    res.cookie("refreshToken", refreshToken, cookieOptionsRefresh);


    // Respond with sanitized user
    return res
      .status(200)
      .json(new ApiResponse(200, user.toJSON(), "User logged in successfully"));
  }
);
const refreshAccessToken = asyncHandler(
  async (_req: Request, res: Response) => {
    const token = _req.cookies?.refreshToken || _req.headers["x-refresh-token"]; // support cookie or header
    if (!token || typeof token !== "string") {
      throw new ApiError(401, "Refresh token missing");
    }

    const secret = process.env.REFRESH_TOKEN_SECRET;
    if (!secret) throw new ApiError(500, "Server misconfiguration");

    let payload: any;
    try {
      payload = jwt.verify(token, secret) as { sub: string };
    } catch {
      throw new ApiError(401, "Invalid refresh token");
    }

    const user = await User.findById(payload.sub);
    if (!user) throw new ApiError(401, "Invalid refresh token");

    const accessToken = user.generateAccessToken();

    const isProd = process.env.NODE_ENV === "production";
    const cookieOptionsAccess = {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? ("none" as const) : ("lax" as const),
      maxAge: 1000 * 60 * 15, // 15 minutes
      path: "/",
    };

    res.cookie("accessToken", accessToken, cookieOptionsAccess);

    return res
      .status(200)
      .json(new ApiResponse(200, { accessToken }, "Access token refreshed"));
  }
);

const logoutUser = asyncHandler(async (req: Request, res: Response) => {
  console.log(",dfkfbdkffd")
  const isProd = process.env.NODE_ENV === "production";
  const cookieOptions = {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? ("none" as const) : ("lax" as const),
    path: "/",
  };

  res.clearCookie("accessToken", cookieOptions);
  res.clearCookie("refreshToken", cookieOptions);

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Logged out successfully"));
});

const getCurrentUser = asyncHandler(async (req: Request, res: Response) => {
  // verifyJWT middleware populates req.user
  console.log("Checking")
  if (!req.user) throw new ApiError(401, "Unauthorized");
  return res.status(200).json(new ApiResponse(200, req.user.toJSON(), "OK"));
});

const forgotPassword = asyncHandler(
  async (req: Request<{}, {}, ForgotPasswordBody>, res: Response) => {
    const email = req.body.email?.toLowerCase();

    if (!email) throw new ApiError(400, "Email is required");

    const user = await User.findOne({ email });

    if (!user) {
      // Respond with 200 to avoid user enumeration
      return res
        .status(200)
        .json(
          new ApiResponse(
            200,
            {},
            "If the account exists, a reset link has been sent"
          )
        );
    }

    const { unHashedToken, hashedToken, tokenExpiry } =
      user.generateTemporaryToken();

    console.log(unHashedToken, hashedToken, tokenExpiry);

    user.forgotPasswordToken = hashedToken;
    user.forgotPasswordExpiry = new Date(tokenExpiry);
    await user.save({ validateBeforeSave: false });

    // TODO: Send email with unHashedToken in a link

    await sendEmail({
      email: user?.email,
      subject: "Password reset request",
      mailgenContent: forgotPasswordMailgenContent({
        username: user.username,
        passwordResetUrl: `${process.env
          .FORGOT_PASSWORD_REDIRECT_URL!}/${unHashedToken}`,
      }),
    });
    return res
      .status(200)
      .json(
        new ApiResponse(
          200,
          { resetToken: unHashedToken },
          "Password reset initiated"
        )
      );
  }
);

const resetPassword = asyncHandler(
  async (req: Request<{}, {}, ResetPasswordBody>, res: Response) => {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) {
      throw new ApiError(400, "Token and newPassword are required");
    }
    if (newPassword.length < 6) {
      throw new ApiError(400, "Password must be at least 6 characters");
    }

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    console.log("The hashedToken is ", hashedToken);
    console.log("The new Date is ", new Date());
    const user = await User.findOne({
      forgotPasswordToken: hashedToken,
      forgotPasswordExpiry: { $gt: new Date() },
    }).select("+password");

    if (!user) throw new ApiError(400, "Invalid or expired token");

    user.password = newPassword; // model hook will hash
    user.forgotPasswordToken = undefined as any;
    user.forgotPasswordExpiry = undefined as any;
    await user.save();

    return res
      .status(200)
      .json(new ApiResponse(200, {}, "Password has been reset"));
  }
);

const verifyEmail = asyncHandler(
  async (req: Request<VerifyEmailBody>, res: Response) => {
    const { token } = req.params;
    if (!token) throw new ApiError(400, "Token is required");

    // const { verificationToken  } = req.params;

    // if (!verificationToken) {
    //   throw new ApiError(400, "Email verification token is missing");
    // }
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      emailVerificationToken: hashedToken,
      emailVerificationExpiry: { $gt: new Date() },
    });

    if (!user) throw new ApiError(400, "Invalid or expired token");

    user.isEmailVerified = true;
    user.emailVerificationToken = undefined as any;
    user.emailVerificationExpiry = undefined as any;
    await user.save({ validateBeforeSave: false });

    return res.status(200).json(new ApiResponse(200, {}, "Email verified"));
  }
);

const resendVerificationEmail = asyncHandler(
  async (req: Request, res: Response) => {
    const user = await User.findById(req.user?._id);

 
    if (!user) {
      // Avoid enumeration
      return res
        .status(200)
        .json(
          new ApiResponse(
            200,
            {},
            "If the account exists, an email has been sent"
          )
        );
    }

    if (user.isEmailVerified) {
      return res
        .status(200)
        .json(new ApiResponse(200, {}, "Email already verified"));
    }

    const { unHashedToken, hashedToken, tokenExpiry } =
      user.generateTemporaryToken();
    user.emailVerificationToken = hashedToken;
    user.emailVerificationExpiry = new Date(tokenExpiry);
    await user.save({ validateBeforeSave: false });

    await sendEmail({
      email: user?.email,
      subject: "Please verify your email",
      mailgenContent: emailVerificationMailgenContent({
        username: user.name,
        verificationUrl: `${req.protocol}://${req.get(
          "host"
        )}/api/v1/users/verify-email/${unHashedToken}`,
      }),
    });
    return res
      .status(200)
      .json(
        new ApiResponse(
          200,
          { verificationToken: unHashedToken },
          "Verification email sent"
        )
      );
  }
);

const changePassword = asyncHandler(
  async (req: Request<{}, {}, ChangePasswordBody>, res: Response) => {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) {
      throw new ApiError(400, "Old and new passwords are required");
    }
    if (newPassword.length < 6) {
      throw new ApiError(400, "New password must be at least 6 characters");
    }

    if (!req.user) throw new ApiError(401, "Unauthorized");

    const user = await User.findById(req.user._id).select("+password");
    if (!user) throw new ApiError(404, "User not found");

    const valid = await user.comparePassword(oldPassword);
    if (!valid) throw new ApiError(401, "Old password is incorrect");

    user.password = newPassword; // model hook will hash
    await user.save();

    return res.status(200).json(new ApiResponse(200, {}, "Password changed"));
  }
);

export {
  registerUser,
  loginUser,
  refreshAccessToken,
  logoutUser,
  getCurrentUser,
  forgotPassword,
  resetPassword,
  verifyEmail,
  resendVerificationEmail,
  changePassword,
};
