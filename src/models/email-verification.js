const mongoose = require('mongoose')

const emailVerificationSchema = new mongoose.Schema({
	
    id: {type: String, required: true },
    email: {type: String, required: [true, "email is required for a verification code"]},
    verificationCode: {type: String, required: true, default: ""},
    expiration: { type: Date, required: true,  default: Date.now() + 1000 * 60 * 60 * 24},
    updated: { type: Date, default: Date.now() },
    // username: { type: String, required: [true, "username is required for setting a verification code"] }
  
})
//export model(<name of Model constructor>, <schema data definition>, <collection to save to>)
module.exports = mongoose.model('EmailVerification', emailVerificationSchema, 'email_verification')