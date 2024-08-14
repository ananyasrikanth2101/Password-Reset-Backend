const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const User = require("./models/User");
const Token = require("./models/Token");

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

mongoose
  .connect(process.env.MONGO_URL)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log(err));

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

const sendPasswordResetEmail = (email, token) => {
  const resetLink = `http://localhost:3000/reset-password/${token}`;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Password Reset Link",
    text: `You requested a password reset. Click the following link to reset your password: ${resetLink}`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Error sending email:", error);
      return { success: false, message: "Failed to send password reset link" };
    } else {
      console.log("Email sent:", info.response);
      return {
        success: true,
        message: "Password reset link sent successfully",
      };
    }
  });
};

app.post("/api/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();
    res.status(201).send({ message: "User registered successfully" });
  } catch (error) {
    res.status(400).send({ message: "User registration failed" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user && (await bcrypt.compare(password, user.password))) {
      res.send({ message: "Login successful" });
    } else {
      res.status(400).send({ message: "Invalid email or password" });
    }
  } catch (error) {
    res.status(400).send({ message: "Login failed" });
  }
});

app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).send({ message: "User not found" });
    }

    const token = new Token({
      userId: user._id,
      token: crypto.randomBytes(32).toString("hex"),
    });
    await token.save();

    const url = `${process.env.CLIENT_URL}/reset-password/${token.token}`;
    await transporter.sendMail({
      from: process.env.EMAIL,
      to: user.email,
      subject: "Password Reset",
      text: `Click on the link to reset your password: ${url}`,
    });

    res.send({ message: "Password reset link sent to your email" });
  } catch (error) {
    res.status(400).send({ message: "Failed to send password reset link" });
  }
});

app.put("/api/reset-password/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;
    const passwordResetToken = await Token.findOne({ token });
    if (!passwordResetToken) {
      return res
        .status(400)
        .send({ message: "Invalid or expired password reset token" });
    }
    const user = await User.findById(passwordResetToken.userId);
    if (!user) {
      return res.status(400).send({ message: "User not found" });
    }
    user.password = await bcrypt.hash(password, 10);
    await user.save();
    await passwordResetToken.deleteOne();
    res.send({ message: "Password reset successful" });
  } catch (error) {
    console.error("Error in reset-password route:", error);
    res.status(400).send({ message: "Password reset failed" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
