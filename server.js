
console.log("started express recipeServer.js")
if(process.env.NODE_ENV !== 'production') {
		require('dotenv').config()
}
const { v4: uuidv4 } = require('uuid');
const session = require('cookie-session'); //helper package for setting cookies in response object
const express = require('express');
const cookieParser = require('cookie-parser'); // in order to read cookie sent from client
const axios = require('axios');
//protect api-endpoint from multiple requests from the same ip

const rateLimit = require('express-rate-limit'); 
function limiter(windowMs, maxRequests) {
	const newLimiter = rateLimit({
	windowMs:  windowMs,
	max: maxRequests
})
return newLimiter
}
//protect api-endpoint from multiple requests from the same ip
const slowDown = require('express-slow-down')
function speedLimiter(windowMs, delayAfter, delayMs) {
	const speedLimiter = slowDown({
		windowMs,
		delayAfter,
		delayMs
	})
	return speedLimiter
} 

//Other options to improve performance is to Cache Results 
//Other options to improce security is to limit requests based on username, API KEY, or JWT
const app = express(); 
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
var helmet = require('helmet');

app.use(helmet()) //express recommended security package
app.use(express.json())
app.use(cookieParser()) //parse client req cookies (unsigned and signed)
console.log("ALLOWED_SERVER_ORIGIN", process.env.ALLOWED_SERVER_ORIGIN)
console.log("EMAIL_SMTP_SERVER_DOMAIN", process.env.EMAIL_SMTP_SERVER_DOMAIN)
app.use(function(req, res, next) {
	const corsWhitelist = [
        `${process.env.ALLOWED_SERVER_ORIGIN}`,
        `${process.env.EMAIL_SMTP_SERVER_DOMAIN}`
	];
	if (corsWhitelist.indexOf(req.headers.origin) !== -1) {
		res.header("Access-Control-Allow-Origin", req.headers.origin); // update to match the domain you will make the request from
	}
	res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
	res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
	res.header("Access-Control-Allow-Credentials", true)
	res.header("Vary", "Origin")
	next();	
  }); //set response headers
  
var expiryDate = 24 * 7 * 60 * 60 * 1000 // 1 week
//connect to mongodb  DATABASE_URL=mongodb://localhost:27017/recipes (already set to recipes database)
const RecipesModel = require('./src/models/recipes');
const User = require('./src/models/users');
const RefreshToken = require('./src/models/refreshTokens');
const EmailVerification = require('./src/models/email-verification')

const mongoose = require('mongoose');
const { create } = require('./src/models/recipes');
mongoose.set('useFindAndModify', false);
mongoose.connect(process.env.DATABASE_URL, { useNewUrlParser: true, useUnifiedTopology: true } )
const db = mongoose.connection
db.on('error', error => console.error(error))
db.once('open', function() {
	console.log("connected to mongoose")
})

//routes
app.get('/', (req,res) => { 
	res.send('You have reached the server backend, are you looking for <a href="https://ironmancct-2-learn-react-today.herokuapp.com">https://ironmancct-2-learn-react-today.herokuapp.com</a> ?')
})

app.get('/recipes', authenticateToken, async (req, res) => {
	console.log("cookies: ", req.cookies)
	//req.user available from authenticateToken middleware
	if(req.isAutheticated == true) {
	console.log(req.user)
	res.json({recipes: await handleRecipesGet(), success: true})
	} else {
		res.status(403).json({message:"No authorization", success: false})
	}

})

app.post('/recipe-add', async (req,res,next) => {
	let newRecipe = { updated: Date.now(), ...req.body }
	await handlePostRecipeAdd(res, newRecipe)
})
app.post('/recipe-upsert', authenticateToken, async (req,res,next) => {
	if(req.isAutheticated===false) return res.status(403).json({success: false, message: "no authorization"})
	let filter = {id: req.body.id}
	let update = { updated: Date.now(), ...req.body }
	res.json(await handlePostRecipeUpsert(filter,update))
})

app.delete('/recipe-delete', async (req, res, next) => {
    console.log('id:', req.body.id)
    console.log(typeof req.body.id)
	res.json(await handleDeleteRecipe( req.body.id))
})
app.post('/api/v1/users/verify-email', limiter((24*60*60 * 1000), 200),  async (req, res, next) => {
	try{
		console.log("creating OTP")
		OTP = createOTP()
		let data = {
			email: req.body.email,
			id: uuidv4(),
			verificationCode: OTP,
			expiration: Date.now() + 1000 * 60 * 60 * 24
		}
		let saveOTPToBackend = await handleSaveOTPtoEmailVerification(data)
		let emailOTPToUser = await handleEmailOTPToUser(data, res)
		res.status(200).send({saveOTPToBackend, emailOTPToUser})
		//await handleEmailOTP(req, res)
	} catch (err) {
		console.log(err)
		res.status(500).send()
	}
})

function createOTP() {
	let OTP = Math.floor(Math.random()* 1000000).toString().padStart(6, "0")
	console.log('OTP: ', OTP)
	return OTP
}

async function handleSaveOTPtoEmailVerification(data) {
	if(data && data.email !=='') {
		try {
			console.log(data)
			let filter = {email: data.email}
			console.log(filter)
			let doc = data
			let options = { new: false, upsert: true } 
			let verificationCodeUpdated = await EmailVerification.findOneAndUpdate(filter, doc, options, function (err, result) {
				if (err) return console.error(err);
				
				console.log(result)
			})
			return verificationCodeUpdated
		} catch (error) {
			return error
		}
	} else {
		return  "no body message recieved"
	}

}

async function handleEmailOTPToUser(data, res) {
	console.log("sending OTP email...")
	let response = axios ({
		method: 'post',
		url: `${process.env.EMAIL_SMTP_SERVER_DOMAIN}/send-email-verification-code`,
		data: data
		})
	.then(response => console.log(response.config))
	.catch(err=>console.log(err))
	return response
}

app.post('/api/v1/users/verification-code', limiter((10 * 60 * 1000), 20), speedLimiter(10 * 60 * 1000, 10, 500), async (req, res) => {
	console.log(req.body)
	if(req.body === null  || req.body.email === '' || req.body.verificationCode === '') return res.status(400).json({message: "bad request", success: false })
	try {
		//check client verification code against server verification code
		let filter = {email: req.body.email} 
		let serverVerificationCode = await EmailVerification.findOne(filter, function(err, doc) {
			if(err) return res.status(400).json({message: 'no user verification code', success: false})
		})
		console.log(serverVerificationCode)
		if (serverVerificationCode === null) return res.status(400).json({message: 'no email-verification-code pair exists, request email verification', success: false})
		console.log(serverVerificationCode.verificationCode)
		if (serverVerificationCode.verificationCode === req.body.verificationCode.toString().trim()) {
			let update = {verified: {email: true}}
			let userVerifiedEmailUpdate = await User.findOneAndUpdate(filter, update,  function(err, doc) {
				if(err) return res.status(500).json({message: 'error updating User verified email', success: false})
			})
			if(userVerifiedEmailUpdate === null) return res.status(400).json({message: "User does not exist", success: false })
			await handleDeleteEmailVerificationByEmail(req.body.email)
			return res.status(200).json({message: "email verified", success: true })
		} else {
			return res.status(404).json({message: "verification code does not match", success: false })
		}
	} catch (err) {
		console.log(err)
		res.status(500).send(err)
	}
})

app.post('/api/v1/users/create', limiter(( 60 * 1000), 5), speedLimiter(10 * 60 * 1000, 5, 500), async (req, res, next) => {
	console.log("request body: ", req.body)
	console.log("request password:", req.body.password)
	const yourPassword = req.body.password
	if(yourPassword === '' || typeof yourPassword !== 'string' )
	{
		return res.status(400).json({success: false, message: "password is empty"})
	}
	else if (!yourPassword.match(/((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W]).{12,64})/)) {
		return res.status(400).json({success: false, message: "password strength is too weak"})
	}

	try {
		const salt = await bcrypt.genSalt()
		const hashedPassword = await bcrypt.hash(yourPassword, salt)
		// console.log(salt)
		// console.log(hashedPassword)
		let newUser = {...req.body, id: uuidv4(), password: hashedPassword, verified: { email: false, phone: false }, updated: Date.now() }
		await createUser(res, newUser)
	}
	catch (err) {
			console.log(err)
			res.send(500).json({message: "server couldn't process your create user srequest", success: false})
		}
})

app.delete('/api/v1/users/delete', async (req, res, next) => {
    // console.log('id:', req.body.id)
	// console.log(typeof req.body.id)
		if (typeof req.body.id === 'string') {
			res.json(await handleDeleteUserById( req.body.id))
			
		} else if (typeof req.body.email === 'string') {
			res.json(await handleDeleteUserByEmail(req.body.email))
		} else {
			res.json("Preflight delete error: request body does not contain email or ID")
		}
	
	}
		
)

app.post('/api/v1/users/login', limiter(( 60 * 1000), 5), speedLimiter(10 * 60 * 1000, 5, 500), async (req, res, next) => {
	try {
		if(typeof req.body.email === 'string' && req.body.email !== '' 	
			&& typeof req.body.password === 'string' && req.body.password !== '') {
		await handleUserLogin(res, req.body)
		} else {
		return res.json({message: "Preflight login error: request body does not contain email or password", success: false})
		}
	} catch (error) {
		console.log(error)
		return res.status(500).json({message: "error in API endpoint", success: false})
	}
		
	
})




app.delete('/api/v1/users/logout', async (req, res, next) => {
	try {
		if(typeof req.body.username === 'string' && req.body.username !== '') {
			await handleUserLogout(res, req.body.username)

		} else {
			res.status(404).json("Preflight logout error: request body does not contain a valid user")
		}
	} catch (error) {
		console.log(error)
		res.status(500).json(error)
	}
})

app.post('/api/v1/users/token', async (req, res, next) => {
	const refreshToken = req.body.token
	if (refreshToken == null) {
		console.log('post request missing refreshToken')
		return res.status(401).json({message: 'Forbidden missing refreshToken', success: false })
	}
	isRefreshTokenValid = handleIsRefreshTokenValid(res, req.body.token)
	if (!isRefreshTokenValid) return res.status(403).json({message: "invalid refreshToken", success: false})
	jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
		if(err) return res.status(403).json({message: "unable to verify refreshtoken", success: false})
		const accessToken = generateAccessToken({name: user.username})
		return res.status(200).json({accessToken: accessToken})
	})
	
})

//mongoDB requesting fuctions

async function createUser(res, newUser){
	if(typeof newUser === 'object' && newUser.username && newUser.password && newUser.email) {
		if(!await User.exists({username: newUser.username})  && !await User.exists({email: newUser.email})) {
			try {
				const userAdd = new User(newUser)
				const payload = await userAdd.save(function (err) {
					if(err) {return res.send(err)}
					else {console.log(newUser.username + " saved to users collection")}
					//saved!
				console.log(payload) //undefined
					return res.status(201).json({messgae: `user  ${newUser.username} added`, payload: payload, success: true})
				})
			} catch (error) {
				return res.status(500).json(error)
			}
		} else if (await User.exists({username: newUser.username})==true) { 
			console.log(`user ${newUser.username} was submitted to the server but already exists`)
			return res.status(409).json({message: "username already exists!", success: false, reason: "username exists"})
		} else if (await User.exists({email: newUser.email})==true) { 
			console.log(`email ${newUser.email} was submitted to the server but already exists`)
			return res.status(409).json({message: "email already exists!", success: false, reason: "email exists"})
		}
	} else {
		return res.status(400).json("createUser() error: there is a problem with the user object datatype or a missing property (username, password, email)")
	}
}

async function handleDeleteUserById(userId){
	let filter = {id: userId}
    console.log("userId:", userId)
    console.log("filter:", filter)
	if(typeof userId === 'string' && userId !== '') {
		if(userId) {
			try {
				let userIdToDelete = await User.deleteOne(filter)
                console.log(userIdToDelete)
                return userIdToDelete
			} catch (error) {
				return error
			}
		} else {
			return  "no user.id recieved"
		}
	}	else {
		return "id is not a string"
	}	
}

async function handleDeleteUserByEmail(userEmail){
	let filter = {email: userEmail}
    console.log("userEmail:", userEmail)
    console.log("filter:", filter)
	if(typeof userEmail === 'string' && userEmail !== '') {
		if(userEmail) {
			try {
				let userEmailToDelete = await User.deleteMany(filter)
                console.log(userEmailToDelete)
                return userEmailToDelete
			} catch (error) {
				return error
			}
		} else {
			return  "no email recieved"
		}
	}	else {
		return "email is not a string"
	}	
}

async function handleDeleteEmailVerificationByEmail(userEmail){
	let filter = {email: userEmail}
    console.log("userEmail:", userEmail)
    console.log("filter:", filter)
	if(typeof userEmail === 'string' && userEmail !== '') {
		if(userEmail) {
			try {
				let userEmailToDelete = await EmailVerification.deleteMany(filter)
                console.log("deleted email verification entry: ", userEmailToDelete)
                return userEmailToDelete
			} catch (error) {
				return error
			}
		} else {
			return  "no email recieved"
		}
	}	else {
		return "email is not a string"
	}	
}

async function handleDeleteRecipe(recipeId){
	let filter = {id: recipeId}
    console.log("recipeId:", recipeId)
    console.log("filter:", filter)
	if(typeof recipeId === 'string' && recipeId !== '') {
		if(recipeId) {
			try {
				let recipeToDelete = await RecipesModel.deleteOne(filter)
                console.log(recipeToDelete)
                return recipeToDelete
			} catch (error) {
				return error
			}
		} else {
			return  "no reciped.id recieved"
		}
	}	else {
		return "id is not a string"
	}
	
}

async function handleRecipesGet() {
	try {
		const recipes = await RecipesModel.find({});
		//console.log("Recipes: ", recipes)
		return recipes

	}
	catch(err) {
		console.log(err)
		return error
		
	}
}

async function handlePostRecipeAdd(res, newRecipe) {
    if(newRecipe&&  ! await RecipesModel.exists({id: newRecipe.id}))  {
		try {
            let recipeAdd =  new RecipesModel(newRecipe)
			await recipeAdd.save(function (err) {
                if (err) return res.send(err);
                console.log("Document inserted succussfully!");
                return res.json({success: true})

            })  
		} catch (error) {
			return res.json(error)
		}
	} else if (await RecipesModel.exists({id: newRecipe.id})==true){
		return  res.json("id exists already!")
	} else {
        return  res.json("no body message recieved")
    }
}

async function handlePostRecipeUpsert(filter, update) {
	if(update) {
		try {
			let recipeUpserted = await RecipesModel.findOneAndUpdate(filter, update, 
				{ new: true, upsert: true})
			return recipeUpserted
		} catch (error) {
			return error
		}
	} else {
		return  "no body message recieved"
	}
}

//login

async function handleUserLogin(res, body) {
	console.log("body", body)
	console.log('body.hasOwnProperty("email")', body.hasOwnProperty("email"))
	console.log('body.hasOwnProperty("password")', body.hasOwnProperty("password"))
	if(typeof body === 'object' && body.hasOwnProperty("email") && body.hasOwnProperty("password") ) {
		let user
		try {user = await User.find({email: body.email}, "username password email verified", (err, doc) => {
			console.log("doc: ", doc)
			if(err){
				return res.status(400).json({message: "error finding user document", success: false})
			}
			if (doc.length < 1) {return res.status(404).json({
				message: "user email doesn't exists! Please Register",
				success: false,
				reason: "cannot find user"
			})}
			else if (doc.length > 1) {return res.status(400).json({
				message: "error: multiple emails found --not allowed! please contact administrator",
				success: false,
				redirect: {
					email: doc.email,
					location: {pathname: '/registration'}
				}
			})}
			else if (!doc[0].verified.email) return res.status(400).json({
				message: `${doc[0].email}  not verified`,
				success: false, 
				redirect: {
					email: doc[0].email, 
					location: {pathname: '/verify-email'}
				}
			})
		})} catch (err) { return err }
		console.log("user:", user)
		if(user && user.length > 0 && user[0].verified && user[0].verified.email) {
			if (!await bcrypt.compare(body.password, user[0].password)) return res.status(400).json({message: "passwords dont match", success: false})
			console.log(`username: ${user[0].username}`)
			const tokenBody = {username: user[0].username, email: user[0].email}
			console.log("tokenBody: ", tokenBody)
			const accessToken =	generateAccessToken(tokenBody)
			const refreshToken = jwt.sign(tokenBody, process.env.REFRESH_TOKEN_SECRET)
			tokenBody.refreshToken = refreshToken
			tokenBody.id = uuidv4()
			//PUSH REFRESH TOKEN TO DATABASE 
			const refreshTokenObject = new RefreshToken(tokenBody)
			//this will finish saving after the response is sent back to the requester
			payload =  refreshTokenObject.save(function (err) {
				if(err) { 
					console.log(err) 
					return res.send(err)
				}
				console.log(user[0].username + " refreshToken saved to collection")
				//saved!
				console.log(`successful refreshTokenSave with payload: ${refreshTokenObject}`)
				})
		
		
			let cookieOptions = {}
			if(process.env.NODE_ENV !== 'production') {
				cookieOptions = {
				maxAge: expiryDate,
				// httpOnly: process.env.IS_HTTP_RES_COOKIE_HTTP_ONLY,
				// sameSite: 'None',
				// secure: process.env.IS_HTTP_RES_COOKIE_SECURE
				}
			}
			else {
				cookieOptions = {
					maxAge: expiryDate,
					httpOnly: true,
					sameSite: 'None',
					secure: true
					}
			}
			console.log(`${body.email} ${user[0].username} authenticated`)
			return res
				.status(200)
				.cookie('access_token', 'Bearer ' + accessToken, cookieOptions)
				.json({messgae: `user  ${body.email} authenticated`, success: true})
					
			
		} 
		else if (user.length > 0 && user[0].verified.email !== true) {
			return res.status(403).json(
				{
					message: `${body.email}  not verified`,
					success: false, 
					redirect: {
						email: body.email, 
						location: {pathname: '/verify-email'}
					}
				}
			)
		}
		else {
			return res.status(400).json({message: "handleUserLogin() error: there is a problem with the user object datatype or a missing property (username, password, email, etc)", success: false})
		}
		
	}
	else {
		return res.status(400).json({message: "handleUserLogin() error: there is a problem with the user object datatype or a missing property (username, password, email, etc)", success: false})
	}
}

async function handleUserLogout(res, username) {
	const tokenDelete = await RefreshToken.deleteMany({username: username}, function (err) {
		if(err) { 
					console.log(err) 
					return res.send(err)
				}
		})
	
	console.log(user.username + " refreshToken(s) removed from collection")
	return res.status(200).json({message: tokenDelete, success: true})
}

 function authenticateToken(req, res, next) {
	//console.log("req", req)
	console.log("cookies", req.cookies.access_token)
	if(req.cookies.access_token) {
		const authCookie = req.cookies.access_token
		const token = authCookie && authCookie.split(' ')[1] 
		if (token == null) {
			req.isAutheticated = false
			req.success = false
			req.cookie('')
			return res.status(401)	 
		} else {
			jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
				if (err) {
					console.log(err)
					req.isAutheticated = false
					req.cookie('')
					return res.status(403).json({message: "Token no longer valid"})
				} else {
					req.user = user
					console.log("authenticateToken user:", user)
					req.isAutheticated = true
					next()
				}

			})
		}
	} else { 
			console.log('no cookie jwt') 
			req.isAutheticated = false
			next()
	}
}

function generateAccessToken(user) {
	return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '36000m'})
}

function handleIsRefreshTokenValid(res, refreshToken) {
	return true
	next()
}
app.listen( process.env.PORT || 3000)