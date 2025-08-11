import {
    forgotPassword,
  login,
  logout,
  register,
  resetPassword,
  setPassword,
  verifyEmail,
} from "../controllers/authController.js";
import passport from "passport";
import jwt from "jsonwebtoken";
import express from "express";

import authMiddleware from "../middleware/authMiddleware.js"; // authMiddleware-i import et

const router = express.Router();

router.post("/register", register);
router.get("/verify-email", verifyEmail);
router.post("/login", login);
router.post("/logout", logout);

// Yeni 'me' endpointi
router.get("/me", authMiddleware, (req, res) => {
    // authMiddleware-i keçdikdən sonra req.user obyekti mövcud olacaq
    return res.status(200).json({
      message: "Authorized",
      user: req.user,
    });
});

router.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "select_account",
  })
);

// Google callback route
router.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    const token = jwt.sign(
      { id: req.user._id, email: req.user.email, role: req.user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.redirect(process.env.CLIENT_URL); // frontend-ə yönləndir
  }
);


router.post("/set-password", setPassword);


router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);
export default router;
