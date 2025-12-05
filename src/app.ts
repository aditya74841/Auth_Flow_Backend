import express, { Application, Request, Response } from "express";
import userRouter from "./routes/user.routes";
import cors from "cors";
import cookieParser from "cookie-parser";
import { errorHandler } from "./middleware/error.middleware";

const app: Application = express();

app.use(
  cors({
    origin: "http://localhost:3000", // your Next.js frontend
    credentials: true,
  })
);

// Parse cookies so authentication middleware can read tokens set as cookies
app.use(cookieParser());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health Check Route
app.get("/health-check", (req: Request, res: Response) => {
  res.status(200).json({
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    message: "Server is running",
  });
});
app.get("/", (req: Request, res: Response) => {
  res.status(200).json({
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    message: "Server is running",
  });
});
// API Routes
app.use("/api/v1/users", userRouter);

// Error Handler (should be last)
app.use(errorHandler);

export default app;
