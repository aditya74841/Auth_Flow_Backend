import { Request, Response, NextFunction, RequestHandler } from "express";
import jwt from "jsonwebtoken";
import { asyncHandler } from "../utils/asyncHandler";
import { ApiError } from "../utils/ApiError";
import { IUserDocument, User } from "../model/user.model";

// Augment Express Request to include user when authenticated
declare global {
  namespace Express {
    interface Request {
      user?: IUserDocument;
    }
  }
}

// Extract bearer token from Authorization header
function getBearerToken(req: Request): string | undefined {
  const header = req.headers.authorization;
  if (!header) return undefined;
  if (header.startsWith("Bearer ")) return header.substring(7).trim();
  return undefined;
}

export const verifyJWT: RequestHandler = asyncHandler(
  async (req: Request, _res: Response, next: NextFunction) => {
    // Prefer secure cookie first, then Authorization header

    const cookieAccess = req.cookies?.accessToken as string | undefined;
    const bearerToken = getBearerToken(req);
    const token = cookieAccess || bearerToken;

    if (!token) {
      throw new ApiError(401, "Unauthorized request");
    }

    const secret = process.env.ACCESS_TOKEN_SECRET;
    if (!secret) {
      throw new ApiError(
        500,
        "Server misconfiguration: ACCESS_TOKEN_SECRET is missing"
      );
    }

    let payload: any;
    try {
      payload = jwt.verify(token, secret) as { sub: string };
    } catch (err: any) {
      // Clients with a valid refresh token can call the refresh endpoint to obtain a new access token
      throw new ApiError(401, err?.message || "Invalid access token");
    }

    const user = await User.findById(payload.sub).select(
      "-password -forgotPasswordToken -forgotPasswordExpiry -emailVerificationToken -emailVerificationExpiry"
    );

    if (!user) {
      // Clients can attempt to refresh if they still hold a valid refresh token
      throw new ApiError(401, "Invalid access token");
    }

    req.user = user;
    next();
  }
);
