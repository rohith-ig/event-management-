const mongoose = require('mongoose');
require('dotenv').config();

const uri = process.env.DB;

mongoose.connect(uri)
    .then(() => console.log("Connected to MongoDB...."))
    .catch((err) => console.error("Error connecting to MongoDB Atlas:", err));


const userSchema = new mongoose.Schema({
    sid : {type: String,required: true},
    name : {type: String,required: true},
    registered_date : {type: Date,default:Date.now},
    password : {type: String,required:true},
    role : {type:String,default:"User"},
    department : String,
    registered : [String],
    year: Number
},{
    versionKey : false
})

const eventSchema = new mongoose.Schema({
    eid : String,
    title: String,
    date: String,
    time: String,
    venue: String,
    capacity: Number,
    organizer: String,
    tags: [String],
    registered: {type:Number,default:0}
});

const registerSchema = new mongoose.Schema({
    rid : String,
    eid : String,
    sid : String,
    name : String,
    department : String,
    year : Number,
    attendance : {type :Boolean,default: false},
    feedback : {type : String,default : ""}
})

const User = mongoose.model('Userschema',userSchema);
const Event = mongoose.model('Eventschema',eventSchema);
const Register = mongoose.model('Register',registerSchema);

module.exports = {mongoose,User,Event,Register}; // Export the connection object

