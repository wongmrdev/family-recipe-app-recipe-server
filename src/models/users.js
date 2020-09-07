const mongoose = require('mongoose')
const usersSchema = new mongoose.Schema({
	
    id: {type: String, required: true},
    firstName: {type: String, required: false, default: 'firstName'},
    lastName: {type: String, required: false, default: 'lastName'},
    username: {type: String, required: true},
    password: {type: String, required: true},
    updated: { type: Date, default: Date.now() },
    country: { type: String, required: false, default: "" },
    email: { type: String, required: true, default: ""},
    familyMembers: {type: [String], required: true},
    phoneNumber: {type: String, required: false, default: ""},
    OTP: {
            value: {type: String, required: false}, 
            expires: {type: Date, required: true, default: Date.now() + 60 * 1000}
        }
})
//export model(<name of Model constructor>, <schema data definition>, <collection to save to>)
module.exports = mongoose.model('User', usersSchema, 'users')