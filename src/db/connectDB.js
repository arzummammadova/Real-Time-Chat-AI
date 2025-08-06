import mongoose from "mongoose";

const mongoURI = process.env.MONGO_URI;

try {
    mongoose.connect(mongoURI)
    console.log("MongoDB database connected ")
} catch (error) {
    console.log(error)
}