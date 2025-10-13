import { Request, Response, NextFunction, ErrorRequestHandler } from "express";
import mongoose from "mongoose";
import { ApiError } from "../utils/ApiError";

const errorHandler: ErrorRequestHandler = (
  err: Error | ApiError,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  let error: ApiError;

  if (err instanceof ApiError) {
    error = err;
  } else {
    let statusCode = 500;
    let message = err.message || "Something went wrong";
    let errors: string[] = [];

    // Handle specific error types
    if ((err as any).statusCode) {
      statusCode = (err as any).statusCode;
    } else if (err instanceof mongoose.Error.ValidationError) {
      statusCode = 400;
      message = "Validation failed";
      errors = Object.values(err.errors).map((e: any) => e.message);
    } else if (err instanceof mongoose.Error.CastError) {
      statusCode = 400;
      message = `Invalid ${err.path}: ${err.value}`;
    } else if ((err as any).code === 11000) {
      // MongoDB duplicate key error
      statusCode = 409;
      const field = Object.keys((err as any).keyValue || {})[0];
      message = `Duplicate value for ${field}`;
      errors = [`${field} already exists`];
    } else if (err instanceof mongoose.Error) {
      statusCode = 400;
    }
    
    error = new ApiError(statusCode, message, errors, err.stack || "");
  }

  const response = {
    statusCode: error.statusCode,
    message: error.message,
    success: error.success,
    errors: error.errors,
    ...(process.env.NODE_ENV === "development" ? { stack: error.stack } : {}),
  };

  res.status(error.statusCode).json(response);
};

export { errorHandler };
