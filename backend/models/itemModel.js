import mongoose from 'mongoose'
const reviewSchema = mongoose.Schema(
    {
      rating: { type: Number, required: true },
      comment: { type: String, required: true },
      user: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: "User",
      },
    },
    {
      timestamps: true,
    }
  );
  
const itemSchema = mongoose.Schema(
    {
      name: {
        type: String,
        required: true,
        unique:true,
      },
      description: {
        type: String,
        required: true,
      },
      brand:{
        type: String,
        required:true
      },
      category: {
        type: String,
        required: true,
      },
      price: {
        type: Number,
        required: true,
      },
      stock:{
        type: Number,
        required:true
      },
      image: {
        type: String,
        required: true,
      },    
      reviews: [reviewSchema],

  
    },
    {
      timestamps: true,
    }
  )
  

const Item = mongoose.model('Item', itemSchema)

export default Item