
console.log("started express recipeServer.js")
if(process.env.NODE_ENV !== 'production') {
		require('dotenv').config()
}
const { v4: uuidv4 } = require('uuid');
const session = require('cookie-session') //helper package for setting cookies in response object
const express = require('express');
const cookieParser = require('cookie-parser'); // in order to read cookie sent from client

const app = express(); 
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')
var helmet = require('helmet')
console.log("ALLOWED_SERVER_ORIGIN:", process.env.ALLOWED_SERVER_ORIGIN)
app.use(helmet()) //express recommended security package
app.use(express.json())
app.use(cookieParser()) //parse client req cookies (unsigned and signed)
app.use(function(req, res, next) {
	res.header("Access-Control-Allow-Origin", process.env.ALLOWED_SERVER_ORIGIN ); // update to match the domain you will make the request from
	res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
	res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
	res.header("Access-Control-Allow-Credentials", true)
	res.header("Vary", "Origin")
	next();	
  }); //set response headers
  
var expiryDate = new Date(Date.now() + 60 * 60 * 1000) // 1 hour
//connect to mongodb  DATABASE_URL=mongodb://localhost:27017/recipes (already set to recipes database)
const RecipesModel = require('./src/models/recipes');
const User = require('./src/models/users');
const RefreshToken = require('./src/models/refreshTokens');
const mongoose = require('mongoose');
mongoose.set('useFindAndModify', false);
mongoose.connect(process.env.DATABASE_URL, { useNewUrlParser: true, useUnifiedTopology: true } )
const db = mongoose.connection
db.on('error', error => console.error(error))
db.once('open', function() {
	console.log("connected to mongoose")
})

//routes
app.get('/recipes', authenticateToken, async (req, res) => {
	console.log("cookies: ", req.cookies)
	//req.user available from authenticateToken middleware
	if(req.isAutheticated == true) {
	console.log(req.user)
	res.json(await handleRecipesGet())
	} else {
		res.status(403).json({message:"No authorization", success: false})
	}

})

app.post('/recipe-add', async (req,res,next) => {
	let newRecipe = { updated: Date.now(), ...req.body }
	await handlePostRecipeAdd(res, newRecipe)
})
app.post('/recipe-upsert', async (req,res,next) => {
	let filter = {id: req.body.id}
	let update = { updated: Date.now(), ...req.body }
	res.json(await handlePostRecipeUpsert(filter,update))
})

app.delete('/recipe-delete', async (req, res, next) => {
    console.log('id:', req.body.id)
    console.log(typeof req.body.id)
	res.json(await handleDeleteRecipe( req.body.id))
})

app.post('/api/v1/users/create', async (req, res, next) => {
	console.log("request body: ", req.body)
	const yourPassword = req.body.password
	const salt = await bcrypt.genSalt()
	const hashedPassword = await bcrypt.hash(yourPassword, salt)
	// console.log(salt)
	// console.log(hashedPassword)
	let newUser = {...req.body, id: uuidv4(), password: hashedPassword, updated: Date.now() }
	await createUser(res, newUser)
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

app.post('/api/v1/users/login', async (req, res, next) => {
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
				console.log(payload)
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
	
	if(typeof body === 'object' && body.email && body.password ) {
		if( await User.exists({email: body.email})) {
				const query =  await User.find({email: body.email}, "username")
				const username = query[0].username
				console.log(`username ${username}`)
				const user = {username: username}
				const accessToken =	generateAccessToken(user)
				const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
				user.refreshToken = refreshToken
				user.id = uuidv4()
				//PUSH REFRESH TOKEN TO DATABASE 
				const refreshTokenObject = new RefreshToken(user)
				//this will finish saving after the response is sent back to the requester
				payload =  refreshTokenObject.save(function (err) {
					if(err) { 
						console.log(err) 
						return res.send(err)
					}
					console.log(user.username + " refreshToken saved to collection")
					//saved!
					console.log(`successful refreshTokenSave with payload: ${refreshTokenObject}`)
					})
			
				console.log(`${body.email} ${username} authenticated`)
				return res
					.status(200)
					.cookie('access_token', 'Bearer ' + accessToken, {
						maxAge: expiryDate,
						httpOnly: true
						})
					.json({messgae: `user  ${body.email} authenticated`, success: true})
					
			
		} else if (!await User.exists({email: body.email})===false) { 
			console.log(`email ${body.email} was submitted to the server cant find that user's email`)
			return res.status(404).json({message: "email doesn't exists!", success: false, reason: "cannot find user"})
	}
	else {
		return res.status(400).json({message: "handleUserLogin() error: there is a problem with the user object datatype or a missing property (username, password, email, etc)", success: false})
	}
}
}

async function handleUserLogout(res, username) {
	const tokenDelete = await RefreshToken.deleteMany({username: username}, function (err) {
		if(err) { 
					console.log(err) 
					return res.send(err)
				}
		})
	return res.status(200).json({message: tokenDelete, success: true})
	console.log(user.username + " refreshToken(s) removed from collection")
	
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