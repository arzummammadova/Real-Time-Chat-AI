import { register, verifyEmail } from "../controllers/authController.js";

import express from "express"
const router=express.Router();

router.post('/register',register)
router.get('/verify-email',verifyEmail)


export default router