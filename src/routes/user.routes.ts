import { Router } from "express";
import {
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
} from "../controller/user.controller";
import { verifyJWT } from "../middleware/auth.middleware";

const router = Router();

// Public routes
router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/refresh", refreshAccessToken);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);
router.get("/verify-email/:token", verifyEmail);
// router.post("/resend-verification", resendVerificationEmail);

// Authenticated routes
router.get("/resend-verification", verifyJWT, resendVerificationEmail);

router.get("/me", verifyJWT, getCurrentUser);
// router.get("/logout", verifyJWT, logoutUser);
router.get("/logout", verifyJWT, logoutUser);

router.post("/change-password", verifyJWT, changePassword);

export default router;
