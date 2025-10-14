import express, { Application } from "express";
import userRouter from "./routes/user.routes";
import cors from "cors";
import { errorHandler } from "./middleware/error.middleware";

const app: Application = express();

app.use(
    cors({
      origin: "http://localhost:3000", // your Next.js frontend
      credentials: true,
    })
  );

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use("/api/v1/users", userRouter);

app.use(errorHandler);

export default app;
