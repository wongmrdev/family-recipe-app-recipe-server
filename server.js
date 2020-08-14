
console.log("started express recipeServer.js")
if(process.NODE_ENV !== 'production') {
		require('dotenv').config()
}
const uuidv4 = require('uuid/v4');
const express = require('express');
const app = express(); 
const bodyParser = require('body-parser');
app.use(express.json())
app.use(function(req, res, next) {
	res.header("Access-Control-Allow-Origin", "*"); // update to match the domain you will make the request from
	res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
	res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
	next();
  });

//connect to mongodb  DATABASE_URL=mongodb://localhost:27017/recipes (already set to recipes database)
const RecipesModel = require('./src/models/recipes');
const mongoose = require('mongoose');
mongoose.set('useFindAndModify', false);
mongoose.connect(process.env.DATABASE_URL, { useNewUrlParser: true, useUnifiedTopology: true } )
const db = mongoose.connection
db.on('error', error => console.error(error))
db.once('open', function() {
	console.log("connected to mongoose")
})

//routes
app.get('/recipes', async (req, res) => {
	res.json(await handleRecipesGet())
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

//mongoDB requesting fuctions


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
			return error
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

app.listen( process.env.PORT || 3000)