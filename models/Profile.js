const mongoose = require('mongoose');
const validator = require('validator');

const ProfileSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true,
  },
  firstName: {
    type: String,
  },
  lastName: {
    type: String,
  },
  email: {
    type: String,
    required: [true, 'Please provide email'],
    requiredvalidate: {
      validator: validator.isEmail,
      message: 'Please provide valid email',
    },
  },
  pictureURL: {
    type: String,
  },
});

module.exports = mongoose.model('Profile', ProfileSchema);
