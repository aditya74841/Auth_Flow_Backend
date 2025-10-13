import { Request, Response, NextFunction, RequestHandler } from "express";

// Generic type that accepts custom request body, params, and query types
type AsyncRequestHandler<
  ReqBody = any,
  ReqParams = any,
  ResBody = any,
  ReqQuery = any
> = (
  req: Request<ReqParams, ResBody, ReqBody, ReqQuery>,
  res: Response<ResBody>,
  next: NextFunction
) => Promise<void | Response<ResBody>>;

const asyncHandler = <
  ReqBody = any,
  ReqParams = any,
  ResBody = any,
  ReqQuery = any
>(
  fn: AsyncRequestHandler<ReqBody, ReqParams, ResBody, ReqQuery>
): RequestHandler<ReqParams, ResBody, ReqBody, ReqQuery> => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

export { asyncHandler };
