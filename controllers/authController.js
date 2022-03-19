const fetch = require('node-fetch');

const User = require('../models/User');
const Profile = require('../models/Profile');

const { StatusCodes } = require('http-status-codes');
const CustomError = require('../errors');
const {
  createJWT,
  sendVerificationEmail,
  sendResetPasswordEmail,
  createHash,
} = require('../utils');
const crypto = require('crypto');

const register = async (req, res) => {
  const { email, password } = req.body;

  const emailAlreadyExists = await User.findOne({ email });
  if (emailAlreadyExists) {
    throw new CustomError.BadRequestError('Email already exists');
  }

  const verificationToken = crypto.randomBytes(40).toString('hex');

  const user = await User.create({
    email,
    password,
    verificationToken,
  });

  if (!user) {
    throw new CustomError.BadRequestError(
      'Something went wrong, please try again later'
    );
  }

  const profile = Profile.create({
    email: user.email,
    userId: user._id,
  });

  if (!profile) {
    User.findByIdAndDelete({ _id: user._id });

    throw new CustomError.BadRequestError(
      'Something went wrong, please try again later'
    );
  }

  await sendVerificationEmail({
    email: user.email,
    verificationToken: user.verificationToken,
    origin: process.env.FRONT_ORIGIN,
  });

  // send verification token back only while testing in postman!!!
  res.status(StatusCodes.CREATED).json({
    msg: 'Success! Please check your email to verify account',
  });
};

const verifyEmail = async (req, res) => {
  const { verificationToken, email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    throw new CustomError.UnauthenticatedError('Verification Failed');
  }

  if (user.verificationToken !== verificationToken) {
    throw new CustomError.UnauthenticatedError('Verification Failed');
  }

  (user.isVerified = true), (user.verified = Date.now());
  user.verificationToken = '';

  await user.save();

  res.status(StatusCodes.OK).json({ msg: 'Email Verified' });
};

const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new CustomError.BadRequestError('Please provide email and password');
  }
  const user = await User.findOne({ email });

  if (!user) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials');
  }
  const isPasswordCorrect = await user.comparePassword(password);

  if (!isPasswordCorrect) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials');
  }
  if (!user.isVerified) {
    throw new CustomError.UnauthenticatedError('Please verify your email');
  }

  const profile = await Profile.findOne({
    email: user.email,
    userId: user._id,
  });

  const jwtToken = createJWT({ payload: profile.toJSON() });

  res.status(StatusCodes.OK).json({ profile: profile, token: jwtToken });
};

const fbLogin = async (req, res) => {
  const { accessToken } = req.body;

  if (!accessToken) {
    throw new CustomError.BadRequestError('Bad request');
  }

  const data = await fetch(
    `https://graph.facebook.com/me?fields=email,first_name,last_name,picture.type(large)&access_token=${accessToken}`
  );

  const result = await data.json();
  if (result.error) {
    throw new CustomError.BadRequestError(result.error.message);
  }

  const profile = await Profile.findOneAndUpdate(
    {
      userId: result.id,
    },
    {
      firstName: result?.first_name,
      lastName: result?.last_name,
      email: result?.email,
      pictureURL: result?.picture?.data?.url,
    },
    {
      upsert: true,
      new: true,
    }
  );

  const jwtToken = createJWT({ payload: profile.toJSON() });

  res.status(StatusCodes.OK).json({ profile: profile, token: jwtToken });
};

const googleLogin = async (req, res) => {
  const { accessToken } = req.body;

  if (!accessToken) {
    throw new CustomError.BadRequestError('Bad request');
  }

  let data = await fetch('https://www.googleapis.com/userinfo/v2/me', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  const result = await data.json();

  if (result.error) {
    throw new CustomError.BadRequestError(result.error.message);
  }

  const profile = await Profile.findOneAndUpdate(
    {
      userId: result.id,
    },
    {
      firstName: result?.given_name,
      lastName: result?.family_name,
      email: result?.email,
      pictureURL: result?.picture,
    },
    {
      upsert: true,
      new: true,
    }
  );

  const jwtToken = createJWT({ payload: profile.toJSON() });

  res.status(StatusCodes.OK).json({ profile: profile, token: jwtToken });
};

const logout = async (req, res) => {
  await Token.findOneAndDelete({ user: req.user.userId });

  res.cookie('accessToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.cookie('refreshToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.status(StatusCodes.OK).json({ msg: 'user logged out!' });
};

const forgotPassword = async (req, res) => {
  const { email } = req.body;
  if (!email) {
    throw new CustomError.BadRequestError('Please provide valid email');
  }

  const user = await User.findOne({ email });

  if (user) {
    const passwordToken = crypto.randomBytes(70).toString('hex');
    // send email
    await sendResetPasswordEmail({
      email: user.email,
      token: passwordToken,
      origin: process.env.FRONT_ORIGIN,
    });

    const tenMinutes = 1000 * 60 * 10;
    const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes);

    user.passwordToken = createHash(passwordToken);
    user.passwordTokenExpirationDate = passwordTokenExpirationDate;
    await user.save();
  }

  res
    .status(StatusCodes.OK)
    .json({ msg: 'Please check your email for reset password link' });
};

const resetPassword = async (req, res) => {
  const { token, email, password } = req.body;
  if (!token || !email || !password) {
    throw new CustomError.BadRequestError('Please provide all values');
  }
  const user = await User.findOne({ email });

  if (user) {
    const currentDate = new Date();

    if (
      user.passwordToken === createHash(token) &&
      user.passwordTokenExpirationDate > currentDate
    ) {
      user.password = password;
      user.passwordToken = null;
      user.passwordTokenExpirationDate = null;
      await user.save();
    }
  }

  res.send('Password changed.');
};

module.exports = {
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
  fbLogin,
  googleLogin,
};
