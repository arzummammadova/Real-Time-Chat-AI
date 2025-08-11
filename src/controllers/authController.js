import {
    loginValidation,
    registerValidation,
} from "../validation/authValidation.js";
import User from "../models/authModel.js";
import bcrypt from "bcrypt";
import { transporter } from "../utils/mailer.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";

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

        return res
            .status(201)
            .json({ message: "User created. Please verify your email" });
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
export const login = async (req, res) => {
    try {
        const { error } = loginValidation.validate(req.body);
        if (error) {
            return res.status(400).json({ message: error.details[0].message });
        }

        const { user, password } = req.body;

        if (!user || !password) {
            return res.status(400).json({ message: "İstifadəçi adı/email və şifrə tələb olunur" });
        }

        const foundUser = await User.findOne({ 
            $or: [
                { email: user.toLowerCase() },
                { username: user }
            ]
        });

        if (!foundUser) {
            return res.status(400).json({ message: "İstifadəçi tapılmadı" });
        }

        const isPasswordValid = await bcrypt.compare(password, foundUser.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: "Şifrə yanlışdır" });
        }

        if (!foundUser.emailVerified) {
            return res.status(400).json({ message: "Zəhmət olmasa emailinizi təsdiqləyin" });
        }

        const token = jwt.sign(
            { id: foundUser._id, email: foundUser.email, role: foundUser.role },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        return res.status(200).json({
            message: "Login successful",
            token,
            user: {
                id: foundUser._id,
                username: foundUser.username,
                email: foundUser.email,
                role: foundUser.role,
            },
        });
    } catch (error) {
        return res.status(500).json({ message: "Server xətası", error: error.message });
    }
};



export const logout = async (req, res) => {
    try {
        // Bu hissə veb tətbiqinizin təhlükəsizlik mexanizmindən asılıdır.
        // Əgər siz JWT token istifadə edirsinizsə:
        // Klient (front-end) sadəcə tokeni silməlidir. Bu halda server tərəfində
        // edəcəyimiz ən yaxşı şey uğurlu bir cavab qaytarmaqdır.
        // Bu funksiya sadəcə bir "success" mesajı qaytaracaq.

        // Əgər siz passport və sessiya istifadə edirsinizsə:
        // req.logout funksiyası mövcud sessiyanı ləğv edir.
        // Bu funksiyanın bəzi versiyaları callback istəyə bilər.
        req.logout((err) => {
            if (err) {
                return res.status(500).json({ message: "Logout failed", error: err.message });
            }
            res.status(200).json({ message: "Logout successful" });
        });

    } catch (error) {
        return res.status(500).json({ message: "Server error", error: error.message });
    }
};
