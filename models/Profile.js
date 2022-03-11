const mongoose = require('mongoose');
const validator = require('validator');

const ProfileSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true,
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

ProfileSchema.index({ email: 1, userId: 1 }, { required: true });

module.exports = mongoose.model('Profile', ProfileSchema);
