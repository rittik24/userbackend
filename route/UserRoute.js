const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const UserModel = require("../modal/UserModal");
const nodemailer = require("nodemailer");
require('dotenv').config();

const UserRouter = express.Router();

const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true, 
  auth: {
    user: process.env.EMAIL,
    pass: process.env.EMAIL_PASS,
  }
});

const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

UserRouter.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const user = await UserModel.findOne({ email });
    if (!user) {
      const hashedPassword = await bcrypt.hash(password, 10);
      const otp = generateOtp();
      const newUser = new UserModel({
        name,
        email,
        password: hashedPassword,
        otp,
        otpExpires: Date.now() + 3600000,
      });
      await newUser.save();

      const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP code is ${otp}. It is valid for one hour.`,
      };

      try {
        await transporter.sendMail(mailOptions);
        res.status(201).json({ msg: "New user has been registered, OTP sent to email" });
      } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).json({ msg: "Error sending email", error: error.message });
      }
    } else {
      res.status(400).json({ msg: "User already exists, please login" });
    }
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ msg: "Something went wrong", error: error.message });
  }
});

UserRouter.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  try {
    const user = await UserModel.findOne({ email });
    if (user) {
      if (user.otp === otp && user.otpExpires > Date.now()) {
        user.otp = null;
        user.otpExpires = null;
        await user.save();
        const token = jwt.sign({ userID: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ msg: "OTP verified successfully", token });
      } else {
        res.status(400).json({ msg: "Invalid or expired OTP" });
      }
    } else {
      res.status(404).json({ msg: "User not found" });
    }
  } catch (error) {
    res.status(500).json({ msg: "Something went wrong", error: error.message });
  }
});

UserRouter.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await UserModel.findOne({ email });
    if (user) {
      const isMatch = await bcrypt.compare(password, user.password);
      if (isMatch) {
        const token = jwt.sign({ userID: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ msg: "Login successful", token });
      } else {
        res.status(401).json({ msg: "Invalid credentials" });
      }
    } else {
      res.status(404).json({ msg: "User not found" });
    }
  } catch (error) {
    console.error('Error logging in user:', error);
    res.status(500).json({ msg: "Something went wrong", error: error.message });
  }
});

UserRouter.get("/users", authenticateToken, async (req, res) => {
  try {
    const users = await UserModel.find({}, "-password -otp -otpExpires");
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ msg: "Something went wrong", error: error.message });
  }
});

UserRouter.put("/users/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, email } = req.body;
  try {
    const user = await UserModel.findByIdAndUpdate(id, { name, email }, { new: true });
    if (!user) return res.status(404).json({ msg: "User not found" });
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ msg: "Something went wrong", error: error.message });
  }
});

UserRouter.delete("/users/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const user = await UserModel.findByIdAndDelete(id);
    if (!user) return res.status(404).json({ msg: "User not found" });
    res.status(200).json({ msg: "User deleted successfully" });
  } catch (error) {
    res.status(500).json({ msg: "Something went wrong", error: error.message });
  }
});

module.exports = UserRouter;
