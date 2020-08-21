const mongoose = require('mongoose')

const refreshTokenSchema = new mongoose.Schema({
	
    id: {type: String, required: true },
    username: {type: String, required: [true, "name is required for a RefreshToken"]},
    refreshToken: {type: String, required: [true, "refresh token is required"]},
    updated: { type: Date, default: Date.now() }
  
})
//export model(<name of Model constructor>, <schema data definition>, <collection to save to>)
module.exports = mongoose.model('RefreshToken', refreshTokenSchema, 'refreshTokens')