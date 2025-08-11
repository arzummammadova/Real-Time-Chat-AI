import mongoose from "mongoose";
const UserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      // Yalnız Google ilə qeydiyyatdan keçməyən istifadəçilər üçün şifrə tələb olunur
      required: function () {
        return !this.googleId;
      },
    },
    role: {
      type: String,
      enum: ["admin", "user"],
      default: "user",
    },
    emailVerified: {
      type: Boolean,
      default: false,
    },
    emailToken: {
      type: String,
    },
    emailTokenExpires: {
      type: Date,
    },
    // Google ilə daxil olan istifadəçiləri fərqləndirmək üçün yeni sahə
    googleId: {
      type: String,
      unique: true,
      sparse: true,
    },
    failedLoginAttempts: {
      type: Number,
      default: 0,
    },
    lockUntil: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true }
);

export default mongoose.model("User", UserSchema);
