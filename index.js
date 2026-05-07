require("dotenv").config();

const express = require("express");
const app = express();

const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { z } = require("zod");

 
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


const signupSchema = z.object({
    name: z.string().min(2).max(100),
    email: z.string().email(),
    password: z.string()
                .min(6)
                .regex(/[A-Z]/, "Must contain one uppercase letter")
                .regex(/[a-z]/, "Must contain one lowercase letter")
                .regex(/[0-9]/, "Must contain one number")
                .regex(/[^A-Za-z0-9]/, "Must contain one special character")

})

function authMiddleware(req, res, next){
    try{
        const authHeader = req.headers.authorization
        const token = authHeader.split(" ")[1];
        const decodedData = jwt.verify(
            token,
            process.env.JWT_SECRET  
        )
        req.user = decodedData;
        next()
    } catch(err){
        res.status(401).json({
            message: "not authorised"
        })
    }
    
}

app.get("/", function(req, res){
    res.json({
        message: "Auth system"
    })
}) 


app.post("/signup", async function(req, res){
    try{
        const { name, email, password } = req.body;
        const result = signupSchema.safeParse(req.body);
        if(!result.success){
            return res.status(400).json({
                message: "Invalid inputs"
            })
        }

        


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
        const token = jwt.sign(
            {
                id: user._id,
                email: user.email
            }, 
            process.env.JWT_SECRET
        )
        res.status(200).json({
            message: "Login successful",
            token
        })
    } catch(err){
        res.status(500).json({
            message: "Something went wrong"
        })

    }
})

app.get("/profile", authMiddleware, async function(req, res){
    res.status(200).json({
        message: "Protected profile route",
        user: req.user
    })
})




app.listen(3000)
