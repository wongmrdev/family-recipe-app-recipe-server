const mongoose = require('mongoose')

const recipesSchema = new mongoose.Schema({
	
    id: {type: String, required: true },
    name: {type: String, required: [true, "name is required for a Recipe"]},
    authors: [
      { id: {type: String, required: true},
        name: {type: String, required: false, default: ""},
        email: {type: String, required: false, default: ""}
      }
    ],
    historicalAuthor:  {type: String, required: false, default: "" },
    originCountry: {type: String, required: false, default: "" },
    originWorldRegion: {type: String, required: false, default: ""},
    servings: {type: Number, required: true, default: ""},
    cookTime: {type: String, required: true, default: ""},
    instructions: {type: String, required: false, default: ""},
    ingredients: [
      {
        id: {type: String, required: true},
        name: {type: String, required: false, default: ""},
        amount: {type: String, required: false, default: ""}
      }
    ],
    updated: { type: Date, default: Date.now() },
    likes: { type: Number, default: 1 }
})
//export model(<name of Model constructor>, <schema data definition>, <collection to save to>)
module.exports = mongoose.model('Recipe', recipesSchema, 'recipes')