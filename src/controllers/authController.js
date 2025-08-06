import { registerValidation } from "../validation/authValidation.js";
import User from "../models/authModel.js";
import bcrypt from "bcrypt";
import { transporter } from "../utils/mailer.js";
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
    user.emailTokeExperies = Date.now() + 1000 * 60 * 60;
    await user.save();
    const verifyURL = `${process.env.SERVER_URL}/api/auth/verify-email?token=${emailToken}?id=${user.id}`;
    await transporter.sendMail({
      from: `Real Time Chat <${process.env}.EMAIL_USER>`,
      to: user.email,
      subject: "E‑poçtunuzu təsdiqləyin",
      html:`
      `
    });

    return res.status(201).json({ message: "User logined successfully!" });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Server error", error: error.message });
  }
};
