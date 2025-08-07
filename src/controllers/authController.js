import { registerValidation } from "../validation/authValidation.js";
import User from "../models/authModel.js";
import bcrypt from "bcrypt";
import { transporter } from "../utils/mailer.js";
import crypto from "crypto";
export const register = async (req, res) => {
  try {
    const { error } = registerValidation.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ message: "Butun saheleri doldur" });
    }
    const userExist = await User.findOne({ $or: [{ email }, { username }] });
    if (userExist) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userCount = await User.countDocuments();
    const role = userCount === 0 ? "admin" : "user";
    const user = await User.create({
      username,
      email,
      password: hashedPassword,
      role,
    });
    const emailToken = crypto.randomBytes(32).toString("hex");
    user.emailToken = emailToken;
    user.emailTokenExpires = Date.now() + 1000 * 60 * 60;
    await user.save();
    const verifyURL = `${process.env.SERVER_URL}/api/auth/verify-email?token=${emailToken}&id=${user._id}`;
    await transporter.sendMail({
      from: `Real Time Chat <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: "E‑poçtunuzu təsdiqləyin",
      html: ` <div style="font-family: Arial, sans-serif; padding: 20px;">
      <h2>Salam, ${user.username}!</h2>
      <p>Real Time Chat platformasına xoş gəlmisiniz. Zəhmət olmasa, hesabınızı təsdiqləmək üçün aşağıdakı düyməyə klikləyin:</p>
      <a href="${verifyURL}" style="display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px; margin-top: 10px;">Hesabı təsdiqlə</a>
      <p style="margin-top: 20px;">Əgər bu e-poçtu siz göndərməmisinizsə, bu mesajı nəzərə almayın.</p>
      <p>Hörmətlə,<br/>Real Time Chat by Arzuui</p>
    </div>`,
    });

    return res.status(201).json({ message: "User created. Please verify your email" });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Server error", error: error.message });
  }
};

export const verifyEmail = async (req, res) => {
  try {
    const { token, id } = req.query;

    const user = await User.findOne({ _id: id, emailToken: token });
    if (!user) {
      return res.status(400).json({ message: "User Not Found" });
    }

    if (user.emailTokenExpires < Date.now()) {
      return res.status(400).json({ message: "Token has expired" });
    }

    user.emailVerified = true;
    user.emailToken = null;
    user.emailTokenExpires = null;
    await user.save();

    return res.status(200).json({ message: "Email verified" });
  } catch (error) {
    return res.status(500).json({ message: "Server error", error });
  }
};


export const login=(res,req)=>({

})