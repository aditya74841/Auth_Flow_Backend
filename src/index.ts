import app from "./app";
import { connectDB } from "./db/intex";
import dotenv from "dotenv";

dotenv.config({
  path: "./.env",
});
const PORT = 8080; 

const startServer = async () => {
  try {
    await connectDB();

    app.listen(PORT, () => {
      console.log(`The server is running at http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
};

startServer();
