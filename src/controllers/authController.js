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
// export const login = async (req, res) => {
//   try {
//     const { error } = loginValidation.validate(req.body);
//     if (error) {
//       return res.status(400).json({ message: error.details[0].message });
//     }

//     const { user, password } = req.body;

//     if (!user || !password) {
//       return res
//         .status(400)
//         .json({ message: "İstifadəçi adı/email və şifrə tələb olunur" });
//     }

//     const foundUser = await User.findOne({
//       $or: [{ email: user.toLowerCase() }, { username: user }],
//     });

//     if (!foundUser) {
//       return res.status(400).json({ message: "İstifadəçi tapılmadı" });
//     }
//     if (!foundUser.password) {
//       // Reset token yarat
//       const resetToken = crypto.randomBytes(32).toString("hex");
//       foundUser.resetPasswordToken = resetToken;
//       foundUser.resetPasswordExpires = Date.now() + 1000 * 60 * 15; // 15 dəqiqəlik
//       await foundUser.save();

//       // Link
//       const resetURL = `${process.env.CLIENT_URL}/set-password?token=${resetToken}&id=${foundUser._id}`;

//       // Mail göndər
//       await transporter.sendMail({
//         from: `Real Time Chat <${process.env.EMAIL_USER}>`,
//         to: foundUser.email,
//         subject: "Şifrə təyin et",
//         html: `
//       <p>Salam, ${foundUser.username}!</p>
//       <p>Google ilə yaratdığınız hesaba şifrə təyin etmək üçün aşağıdakı linkə klikləyin:</p>
//       <a href="${resetURL}">Şifrə təyin et</a>
//       <p>Link 15 dəqiqə ərzində etibarlıdır.</p>
//     `,
//       });

//       return res.status(400).json({
//         message:
//           "Bu hesab Google ilə yaradılıb. Emailinizə şifrə təyin etmə linki göndərildi.",
//       });
//     }

//     const isPasswordValid = await bcrypt.compare(password, foundUser.password);
//     if (!isPasswordValid) {
//       return res.status(400).json({ message: "Şifrə yanlışdır" });
//     }

//     if (!foundUser.emailVerified) {
//       return res
//         .status(400)
//         .json({ message: "Zəhmət olmasa emailinizi təsdiqləyin" });
//     }

//     const token = jwt.sign(
//       { id: foundUser._id, email: foundUser.email, role: foundUser.role },
//       process.env.JWT_SECRET,
//       { expiresIn: "7d" }
//     );

//     // Token cookie-də saxla
//     res.cookie("token", token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//       sameSite: "strict",
//       maxAge: 7 * 24 * 60 * 60 * 1000, // 7 gün
//     });

//     return res.status(200).json({
//       message: "Login successful",
//       user: {
//         id: foundUser._id,
//         username: foundUser.username,
//         email: foundUser.email,
//         role: foundUser.role,
//       },
//     });
//   } catch (error) {
//     return res
//       .status(500)
//       .json({ message: "Server xətası", error: error.message });
//   }
// };


export const login = async (req, res) => {
  try {
    const { error } = loginValidation.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { user, password } = req.body;

    if (!user || !password) {
      return res
        .status(400)
        .json({ message: "İstifadəçi adı/email və şifrə tələb olunur" });
    }

    const foundUser = await User.findOne({
      $or: [{ email: user.toLowerCase() }, { username: user }],
    });

    if (!foundUser) {
      return res.status(400).json({ message: "İstifadəçi tapılmadı" });
    }

    // Hesab bloklanıbsa, yoxla
    if (foundUser.lockUntil && foundUser.lockUntil > Date.now()) {
      const minutesLeft = Math.ceil(
        (foundUser.lockUntil - Date.now()) / (1000 * 60)
      );
      return res.status(403).json({
        message: `Hesabınız müvəqqəti bloklanıb. Zəhmət olmasa ${minutesLeft} dəqiqə sonra yenidən cəhd edin.`,
      });
    }

    // Google ilə yaradılıbsa və şifrə yoxdursa, şifrə təyin etmə linki göndər
    if (!foundUser.password) {
      // Reset token yarat
      const resetToken = crypto.randomBytes(32).toString("hex");
      foundUser.resetPasswordToken = resetToken;
      foundUser.resetPasswordExpires = Date.now() + 1000 * 60 * 15; // 15 dəqiqəlik
      await foundUser.save();

      // Link
      const resetURL = `${process.env.CLIENT_URL}/set-password?token=${resetToken}&id=${foundUser._id}`;

      // Mail göndər
      await transporter.sendMail({
        from: `Real Time Chat <${process.env.EMAIL_USER}>`,
        to: foundUser.email,
        subject: "Şifrə təyin et",
        html: `
          <p>Salam, ${foundUser.username}!</p>
          <p>Google ilə yaratdığınız hesaba şifrə təyin etmək üçün aşağıdakı linkə klikləyin:</p>
          <a href="${resetURL}">Şifrə təyin et</a>
          <p>Link 15 dəqiqə ərzində etibarlıdır.</p>
        `,
      });

      return res.status(400).json({
        message:
          "Bu hesab Google ilə yaradılıb. Emailinizə şifrə təyin etmə linki göndərildi.",
      });
    }

    const isPasswordValid = await bcrypt.compare(password, foundUser.password);

    if (!isPasswordValid) {
      // Səhv şifrə olduqda failedLoginAttempts artır
      foundUser.failedLoginAttempts = (foundUser.failedLoginAttempts || 0) + 1;

      // 5 cəhddən sonra hesabı blokla 15 dəqiqə üçün
      if (foundUser.failedLoginAttempts >= 5) {
        foundUser.lockUntil = Date.now() + 15 * 60 * 1000; // 15 dəqiqə bloklama
        await foundUser.save();
        return res.status(403).json({
          message:
            "Hesabınız çoxsaylı səhv cəhdlər səbəbindən 15 dəqiqəlik bloklandı.",
        });
      }

      await foundUser.save();

      return res.status(400).json({ message: "Şifrə yanlışdır" });
    }

    // Uğurlu login olduqda cəhd sayını sıfırla, lockUntil-u null et
    foundUser.failedLoginAttempts = 0;
    foundUser.lockUntil = null;
    await foundUser.save();

    if (!foundUser.emailVerified) {
      return res
        .status(400)
        .json({ message: "Zəhmət olmasa emailinizi təsdiqləyin" });
    }

    const token = jwt.sign(
      { id: foundUser._id, email: foundUser.email, role: foundUser.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Token cookie-də saxla
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 gün
    });

    return res.status(200).json({
      message: "Login successful",
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
    // Çərəzdən tokeni silin
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    return res.status(200).json({ message: "Logout successful" });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Server xətası", error: error.message });
  }
};


export const setPassword = async (req, res) => {
  try {
    const { token, id, password } = req.body;
    if (!password) {
      return res.status(400).json({ message: "Şifrə tələb olunur" });
    }

    const user = await User.findOne({
      _id: id,
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: "Token etibarsız və ya vaxtı bitib" });
    }

    user.password = await bcrypt.hash(password, 10);
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    await user.save();

    return res.status(200).json({ message: "Şifrə uğurla təyin edildi" });
  } catch (error) {
    return res.status(500).json({ message: "Server xətası", error: error.message });
  }
};


export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ message: "Email tələb olunur" });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      // təhlükəsizlik üçün demirik "istifadəçi yoxdur"
      return res.status(200).json({
        message: "Əgər email qeydiyyatdadırsa, şifrə yeniləmə linki göndərildi.",
      });
    }

    // Token yarat
    const resetToken = crypto.randomBytes(32).toString("hex");
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 1000 * 60 * 15; // 15 dəq

    await user.save();

    // Reset link
    const resetURL = `${process.env.CLIENT_URL}/reset-password?token=${resetToken}&id=${user._id}`;

    // Mail göndər
    await transporter.sendMail({
      from: `Real Time Chat <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: "Şifrə yeniləmə linki",
      html: `
        <p>Salam, ${user.username}!</p>
        <p>Şifrənizi yeniləmək üçün aşağıdakı linkə klikləyin:</p>
        <a href="${resetURL}">Şifrəni yenilə</a>
        <p>Link 15 dəqiqə ərzində etibarlıdır.</p>
      `,
    });

    return res.status(200).json({
      message: "Əgər email qeydiyyatdadırsa, şifrə yeniləmə linki göndərildi.",
    });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Server xətası", error: error.message });
  }
};

export const resetPassword = async (req, res) => {
  try {
    const { id, token, password } = req.body;

    if (!password) {
      return res.status(400).json({ message: "Yeni şifrə tələb olunur" });
    }

    const user = await User.findOne({
      _id: id,
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }, // token hələ keçərli olmalıdır
    });

    if (!user) {
      return res
        .status(400)
        .json({ message: "Token etibarsızdır və ya vaxtı keçib" });
    }

    user.password = await bcrypt.hash(password, 10);
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;

    await user.save();

    return res.status(200).json({ message: "Şifrə uğurla yeniləndi" });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Server xətası", error: error.message });
  }
};