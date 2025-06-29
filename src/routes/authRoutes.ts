import express from "express";
import {
    login,
    refresh,
    protectedRoute,
    logout,
    sendCodeCheck,
    verifyCode,
    register,
} from "../controllers/authController";
import { authenticate } from "../middleware/authMiddleware";

export const authRoutes = express.Router();

authRoutes.post("/send_code", sendCodeCheck);
authRoutes.post("/verify", verifyCode);
authRoutes.post("/register", register);
authRoutes.post("/login", login);
authRoutes.post("/logout", logout);
authRoutes.post("/refresh", refresh);
authRoutes.get("/refresh", refresh);
authRoutes.get("/protected", authenticate, protectedRoute);
