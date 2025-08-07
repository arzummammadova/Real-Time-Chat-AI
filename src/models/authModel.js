import mongoose from "mongoose"
const UserSchema=new mongoose.Schema({
    username:{
        type:String,
        required:true,
        unique:true,
    },
    email:{
        type:String,
        required:true,
        unique:true,

    },
    password:{
        type:String,
        required:true,

    },
    role:{
        type:String,
        enum:["admin","user"],
        default:"user",
    },
    emailVerified: {
  type: Boolean,
  default: false,
},

    emailToken:{
        type:String,
    },
    emailTokenExpires:{
        type:Date,
    }
    
},{timestamps:true})


export default mongoose.model("User",UserSchema)