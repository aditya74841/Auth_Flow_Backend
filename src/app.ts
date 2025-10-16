import express, { Application } from "express";
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

app.use("/api/v1/users", userRouter);

app.use(errorHandler);

export default app;
