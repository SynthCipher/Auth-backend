import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
import transporter from "../config/nodemailer.js";
import {
  EMAIL_VERIFY_TEMPLATE,
  PASSWORD_RESET_TEMPLATE,
} from "../config/emailTemplates.js";

// API FOR USER REGISTRATION
const register = async (req, res) => {
  const { name, email, password } = req.body;

  if (!email || !name || !password) {
    return res.json({ success: false, message: "Missing Details" });
  }

  try {
    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return res.json({ success: false, message: "Email already Exist" });
    }

    const hashedPassword = await bcrypt.hash(password, 10); // const salt = await bcrypt.genSalt(10);

    const user = new userModel({
      name,
      email,
      password: hashedPassword,
    });
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 60 * 60 * 24 * 7 * 1000,
    });

    // Sending welcom email
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "Welcome to OneLadakh",
      text: `Welcome to OneLadakh,Your Account has been created with the email id : ${email} `,
    };
    await transporter.sendMail(mailOptions);

    return res.json({ success: true, message: "Account successfully created" });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

// API FOR USER LOGIN
const login = async (req, res) => {
  const { email, password } = req.body;
  // const { email, password,username } = req.body;

  if (!email || !password) {
    // if ((!email && !username) || !password) {
    return res.json({
      success: false,
      message: "Email and password are required",
    });
  }

  try {
    const user = await userModel.findOne({ email });
    // const user = await userModel.findOne({
    //   $or: [{ email }, { username }]
    // });
    if (!user) {
      return res.json({ success: false, message: "Invalid email" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.json({ success: false, message: "Invalid password" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 60 * 60 * 24 * 7 * 1000,
    });
    return res.json({ success: true, message: "Login successful" });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

// API FOR LOGOUT
const logout = async (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 60 * 60 * 24 * 7 * 1000,
    });

    return res.json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

// API TO SEND VERIFICATION OTP TO THE USER'S EMAIL
const sendVerifyOtp = async (req, res) => {
  try {
    const { userId } = req.body;
    const user = await userModel.findById(userId);
    if (user.isAccountVerified) {
      return res.json({ success: false, message: "Account Already verified" });
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    user.verifyOtp = otp;
    user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;
    await user.save();

    const mailOption = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Account Verification OTP",
      // text: `Your OTP is ${otp}.Verify your account using this OTP. `,
      html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace(
        "{{email}}",
        user.email
      ),
    };
    await transporter.sendMail(mailOption);

    return res.json({
      success: true,
      message: "Verification OTP Sent on Email",
    });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

// API TO VERIFY THE EMAIL USING SENT OTP
const verifyEmail = async (req, res) => {
  const { userId, otp } = req.body;

  if (!userId || !otp) {
    return res.json({ success: false, message: "Missing Details" });
  }

  try {
    const user = await userModel.findById(userId);
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }
    if (user.verifyOtp === "" || user.verifyOtp !== otp) {
      return res.json({ success: false, message: "Invalid OTP" });
    }
    if (user.verifyOtpExpireAt < Date.now()) {
      return res.json({ success: false, message: "OTP Expired" });
    }

    user.isAccountVerified = true;
    user.verifyOtp = "";
    user.verifyOtpExpireAt = 0;
    await user.save();

    return res.json({ success: true, message: "Email Verified Successfully" });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

// API TO check user IS  AUTHENTICATED
const isAuthenticated = async (req, res) => {
  try {
    return res.json({ success: true, message: "Session is active" });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

// Send Password RESET OTP
const sendResetOtp = async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.json({ sucess: false, message: "Email is required" });
  }

  try {
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.json({ sucess: false, message: "Email not found" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);
    user.resetOtp = otp;
    user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;
    user.save();

    const mailOption = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Password Reset OTP",
      text: `Your OTP is ${otp}.Reset your password using this OTP and Please use it within the next 15 minutes before it expires. `,
      html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace(
        "{{email}}",
        user.email
      ),
    };
    await transporter.sendMail(mailOption);

    return res.json({ success: true, message: "OTP sent to your email" });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

// API FOR VERIFY RESET PASSWORD OTP
const verifyResetPasswordOtp = async (req, res) => {
  const { email, otp } = req.body;
  // console.log(email,otp)

  if (!email || !otp) {
    return res.send({
      success: false,
      message: "Email and OTP are required",
    });
  }
  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.send({ success: false, message: "User not found" });
    }
    if (user.resetOtp === "" || user.resetOtp !== otp) {
      return res.send({ success: false, message: "Invalid OTP" });
    }

    if (user.resetOtpExpireAt < Date.now()) {
      return res.json({ success: false, message: "OTP Expired" });
    }

    return res.json({
      success: true,
      message: "OTP is verified succesfully",
    });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

// RESET USER PASSWORD
// const resetPassword = async (req, res) => {
//   const { email, newPassword } = req.body;

//   if (!email  || !newPassword) {
//     return res.send({
//       success: false,
//       message: "Email, OTP , and new Password are required",
//     });
//   }
//   try {
//     const user = await userModel.findOne({ email });
//     if (!user) {
//       return res.send({ success: false, message: "User not found" });
//     }

//     const hashedPassword = await bcrypt.hash(newPassword, 10);

//     user.password = hashedPassword;
//     user.resetOtp = "";
//     user.resetOtpExpireAt = 0;
//     await user.save();

//     return res.json({
//       success: true,
//       message: "Password has been reset succesfully updated.",
//     });
//   } catch (error) {
//     res.json({ success: false, message: error.message });
//   }
// };

// RESET USER PASSWORD
const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if(!email || !otp || !newPassword){
    return res.send({ success: false, message: "Email, OTP , and new Password are required" });

  }
  try {
    const user = await userModel.findOne({ email });
    if(!user){
      return res.send({ success: false, message: "User not found" });

    }
    if (user.resetOtp === "" || user.resetOtp !== otp) {
      return res.send({ success: false, message: "Invalid OTP" });
    }

    if (user.resetOtpExpireAt < Date.now()) {
      return res.json({ success: false, message: "OTP Expired" });
    }

    const hashedPassword = await bcrypt.hash(newPassword,10);

    user.password = hashedPassword;
    user.resetOtp = "";
    user.resetOtpExpireAt = 0;
    user.save();

    return res.json({ success: true, message: "Password has been reset succesfully" });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};


export {
  register,
  login,
  logout,
  sendVerifyOtp,
  verifyEmail,
  isAuthenticated,
  sendResetOtp,
  resetPassword,
  verifyResetPasswordOtp
};

// RESET USER PASSWORD
// const resetPassword = async (req, res) => {
//   const { email, otp, newPassword } = req.body;

//   if(!email || !otp || !newPassword){
//     return res.send({ success: false, message: "Email, OTP , and new Password are required" });

//   }
//   try {
//     const user = await userModel.findOne({ email });
//     if(!user){
//       return res.send({ success: false, message: "User not found" });

//     }
//     if (user.resetOtp === "" || user.resetOtp !== otp) {
//       return res.send({ success: false, message: "Invalid OTP" });
//     }

//     if (user.resetOtpExpireAt < Date.now()) {
//       return res.json({ success: false, message: "OTP Expired" });
//     }

//     const hashedPassword = await bcrypt.hash(newPassword,10);

//     user.password = hashedPassword;
//     user.resetOtp = "";
//     user.resetOtpExpireAt = 0;
//     user.save();

//     return res.json({ success: true, message: "Password has been reset succesfully" });
//   } catch (error) {
//     res.json({ success: false, message: error.message });
//   }
// };
