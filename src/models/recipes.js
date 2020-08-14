const mongoose = require('mongoose')

const recipesSchema = new mongoose.Schema({
	
    id: {type: String, required: true },
    name: {type: String, required: [true, "name is required for a Recipe"]},
    servings: {type: Number, required: true},
    cookTime: {type: String, required: true},
    instructions: {type: String, required: false},
    ingredients: [
      {
        id: {type: String, required: true},
        name: {type: String, required: false},
        amount: {type: String, required: false}
      }
    ],
    updated: { type: Date, default: Date.now() }
  
})
//export model(<name of Model constructor>, <schema data definition>, <collection to save to>)
module.exports = mongoose.model('Recipe', recipesSchema, 'recipes')