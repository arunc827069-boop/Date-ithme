const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());
app.use(cors({origin:"http://localhost:5500"})); // Only frontend

const JWT_SECRET = "dateMeSecretKey123!"; // secret for token

mongoose.connect('mongodb://localhost:27017/dateme-secure',{
    useNewUrlParser:true,
    useUnifiedTopology:true
});

// User Schema
const userSchema = new mongoose.Schema({
    userID: String,
    name: String,
    username: String,
    password: String, // hashed
    age: Number,
    bio: String,
    image: String,
    interests: [String],
    likedUsers: [String],
    dislikedUsers: [String]
});

const User = mongoose.model('User', userSchema);

// Signup
app.post('/signup', async (req,res)=>{
    const {name, username, password, age, bio, image, interests} = req.body;

    if(!name || !username || !password){
        return res.status(400).json({success:false, msg:"All fields required"});
    }

    const existingUser = await User.findOne({username});
    if(existingUser) return res.status(400).json({success:false, msg:"Username exists"});

    const hashedPassword = await bcrypt.hash(password,10);
    const count = await User.countDocuments();
    const userID = "DM" + (count+1).toString().padStart(5,'0');

    const newUser = new User({
        userID, name, username, password:hashedPassword, age, bio, image, interests,
        likedUsers:[], dislikedUsers:[]
    });

    await newUser.save();
    res.json({success:true, userID});
});

// Login
app.post('/login', async (req,res)=>{
    const {username,password} = req.body;
    const user = await User.findOne({username});
    if(!user) return res.status(400).json({success:false, msg:"Invalid credentials"});

    const match = await bcrypt.compare(password, user.password);
    if(!match) return res.status(400).json({success:false, msg:"Invalid credentials"});

    const token = jwt.sign({userID:user.userID}, JWT_SECRET, {expiresIn:'7d'});
    res.json({success:true, token, userID:user.userID, name:user.name});
});

// Middleware: verify JWT
function auth(req,res,next){
    const token = req.headers['authorization'];
    if(!token) return res.status(401).json({msg:"No token"});
    try{
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userID = decoded.userID;
        next();
    }catch(e){
        return res.status(401).json({msg:"Invalid token"});
    }
}

// Get all users (except current) – protected
app.get('/users', auth, async (req,res)=>{
    const users = await User.find({userID: {$ne: req.userID}});
    res.json(users);
});

// Like
app.post('/like', auth, async (req,res)=>{
    const {likedID} = req.body;
    if(likedID === req.userID) return res.status(400).json({msg:"Cannot like self"});
    await User.updateOne({userID:req.userID}, {$addToSet:{likedUsers:likedID}});
    res.json({success:true});
});

// Dislike
app.post('/dislike', auth, async (req,res)=>{
    const {dislikedID} = req.body;
    if(dislikedID === req.userID) return res.status(400).json({msg:"Cannot dislike self"});
    await User.updateOne({userID:req.userID}, {$addToSet:{dislikedUsers:dislikedID}});
    res.json({success:true});
});

app.listen(3000, ()=>console.log("Server running on port 3000"));
