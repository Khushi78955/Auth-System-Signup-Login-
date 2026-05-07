require("dotenv").config();

const express = require("express");
const app = express();

const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

app.use(express.json());

mongoose.connect(process.env.MONGO_URL);


const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String
}, {
    timestamps: true
})

const User = mongoose.model("User", userSchema);

app.get("/", function(req, res){
    res.json({
        message: "Auth system"
    })
})


app.post("/signup", async function(req, res){
    try{
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10)
        const response = await User.create({
            name,
            email,
            password: hashedPassword
        })
        res.status(201).json(response)
    } catch(err){
        res.status(500).json({
            message: "something went wrong"
        })
    } 
})


app.post("/login", async function(req, res){
    try{
        const { email, password } = req.body;
        const user = await User.findOne({
            email
        })
        if(!user){
            return res.status(401).json({
                message: "Invalid credentials"
            })
        }
        const isMatch = await bcrypt.compare(password, user.password)
        if(!isMatch){
            return res.status(401).json({
                message: "Invalid credentials"
            })
        }
        res.status(200).json({
            message: "Login successful"
        })
    } catch(err){
        res.status(500).json({
            message: "Something went wrong"
        })

    }
})

app.listen(3000)
