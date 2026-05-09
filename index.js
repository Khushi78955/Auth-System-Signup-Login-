require("dotenv").config();

const express = require("express");
const app = express();

const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { z } = require("zod");
const cookieParser = require("cookie-parser");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;;
const session = require("express-session");
const rateLimit = require("express-rate-limit")
const crypto = require("crypto")
 
app.use(express.json());
app.use(cookieParser());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax"
    }
}))
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect(process.env.MONGO_URL);


const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    refreshToken: String, 
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    role: {
        type: String,
        enum: ["user", "admin"],
        default: "user"
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    verificationToken: String
}, {
    timestamps: true
})



const User = mongoose.model("User", userSchema);

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
},
async function(accessToken, refreshToken, profile, done){
    try{
        let user = await User.findOne({
            email: profile.emails[0].value
        })
        if(!user){
            user = await User.create({
                name: profile.displayName,
                email: profile.emails[0].value,
                password: ""
            })
        }
        done(null, user);
    } catch(err){
        done(err, null)
    }
}))


passport.serializeUser(function(user, done){
    done(null, user._id)
})

passport.deserializeUser(async function(id, done){
    try{
        const user = await User.findById(id);
        done(null, user)
    } catch(err){
        done(err, null)
    }
    
})




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
        // const token = req.headers.authorization
        const token = req.cookies.accessToken

        if(!token){
            return res.status(401).json({
                message: "Token missing"
            })
        }  

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

function adminMiddleware(req, res, next){
    if(req.user.role !== "admin"){
        return res.status(403).json({
            message: "Admins only"
        })
    }
    next()
}

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: {
        message: "Too many login attempts. Try again later"
    }
})




app.get("/", function(req, res){
    res.json({
        message: "Auth system"
    })
}) 



app.get("/admin", authMiddleware, adminMiddleware, function(req, res){
    res.status(200).json({
        message: "welcome admin"
    })
})



app.get("/auth/google",
    passport.authenticate("google", {
        scope: ["profile", "email"]
    })
)



app.get("/auth/google/callback",
    passport.authenticate("google", {
        failureRedirect: "/login"
    }),
    async function(req, res){
        const accessToken = jwt.sign(
            {
                id: req.user._id,
                email: req.user.email,
                role: req.user.role
            },
            process.env.JWT_SECRET,
            {
                expiresIn: "15m"
            }
        ) 
        const refreshToken = jwt.sign(
            {
                id: req.user._id
            },
            process.env.JWT_REFRESH_SECRET,
            {
                expiresIn: "7d"
            }
        )
        
        req.user.refreshToken = refreshToken;
        await req.user.save();


        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 15 * 60 * 1000
        })
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000
        })
        res.status(200).json({
            message: "Google login successful"
        })


    }
)



app.post("/signup", async function(req, res){
    try{
        const { name, email, password } = req.body;
        const result = signupSchema.safeParse(req.body);
        if(!result.success){
            return res.status(400).json({
                message: "Invalid inputs"
            })
        }

        const existingUser = await User.findOne({
            email
        })
        if(existingUser){
            return res.status(400).json({
                message: "User already exists"
            })
        }

        const hashedPassword = await bcrypt.hash(password, 10)
        const verificationToken = crypto.randomBytes(32).toString("hex")

        const response = await User.create({
            name,
            email,
            password: hashedPassword,
            verificationToken
        })

        const verificationLink = `http://localhost:3000/verify/${verificationToken}`
        console.log(verificationLink)

        res.status(201).json({
            message: "Signup successful",
            user: {
                id: response._id,
                name: response.name,
                email: response.email
            }
        })
    } catch(err){
        res.status(500).json({
            message: "something went wrong"
        })
    } 
})



app.get("/verify/:token", async function(req, res){
    try{
        const token = req.params.token
        const user = await User.findOne({
            verificationToken: token
        })
        if(!user){
            return res.status(400).json({
                message: "Invalid token"
            })
        }

        user.isVerified = true
        user.verificationToken = ""
        
        await user.save()

        res.status(200).json({
            message: "email verified successfully"
        })
    } catch(err){
        res.status(500).json({
            message: "Something went wrong"
        })
    }
})



app.post("/forget-password", async function(req, res){
    try{
        const { email } = req.body;
        const user = await User.findOne({email});
        if(!user){
            return res.status(404).json({
                message: "User not found"
            })
        }
        const resetToken = crypto.randomBytes(32).toString("hex");
        user.resetPasswordToken = resetToken
        user.resetPasswordExpires = Date.now() + 15 * 60 * 1000;

        await user.save();

        const resetLink = `http://localhost:3000/reset-password/${resetToken}`;
        console.log(resetLink);

        res.status(200).json({
            message: "Password reset link generated"
        })
    } catch(err){
        res.status(500).json({
            message: "Something went wrong"
        })
    }
    


})



app.post("/reset-password/:token", async function(req, res){
    try{
        const token = req.params.token;
        const { password } = req.body;
        const user = await User.findOne({
            resetPasswordToken: token
        })

        if(!user){
            return res.status(400).json({
                message: "Invalid Token"
            })
        }

        if(user.resetPasswordExpires < Date.now()){
            return res.status(400).json({
                message: "Token expired"
            })
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;

        user.resetPasswordToken = ""
        user.resetPasswordExpires = null

        await user.save();

        return res.status(200).json({
            message: "Password reset successful"
        })
    } catch(err){
        return res.status(500).json({
            message: "Something went wrong"
        })
    }
    
})



app.post("/login", loginLimiter, async function(req, res){
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

        if(!user.isVerified){
            return res.status(403).json({
                message: "Please verify your email address"
            })
        }
        const accessToken = jwt.sign(
            {
                id: user._id,
                email: user.email,
                role: user.role
            }, 
            process.env.JWT_SECRET,
            {
                expiresIn: "15m"
            }
        )
        const refreshToken = jwt.sign(
            {
                id: user._id
            },
            process.env.JWT_REFRESH_SECRET,
            {
                expiresIn: "7d"
            }
        )
        user.refreshToken = refreshToken;
        await user.save()

        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 15 * 60 * 1000
        })

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000
        })


        res.status(200).json({
            message: "Login successful"
        })
    } catch(err){
        res.status(500).json({
            message: "Something went wrong"
        })

    }
})



app.post("/logout", async function(req, res){
    try{
        const refreshToken = req.cookies.refreshToken;
        if(refreshToken){
            const decoded = jwt.verify(
                refreshToken,
                process.env.JWT_REFRESH_SECRET
            )

            const user = await User.findById(decoded.id);

            if(user){
                user.refreshToken = "";
                await user.save()
            }

            res.clearCookie("accessToken", {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "lax"
            });

            res.clearCookie("refreshToken", {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "lax"
            });
            
            res.status(200).json({
                message: "Logout successful"
            })
        }
    } catch(err){
        res.status(200).json({
            message: "Logged out"
        })
    }
    
})



app.post("/refresh", async function(req, res){
    try{
        // const { refreshToken } = req.body;
        const refreshToken = req.cookies.refreshToken;
        if(!refreshToken){
            return res.status(401).json({
                message: "Refresh token required"
            })
        }
        const decoded = jwt.verify(
            refreshToken,
            process.env.JWT_REFRESH_SECRET
        )

        const user = await User.findById(decoded.id);

        if(!user || user.refreshToken !== refreshToken){
            return res.status(403).json({
                message: "Invalid refresh Token"
            })
        }

        const newAccessToken = jwt.sign(
            {
                id: user._id,
                email: user.email, 
                role: user.role
            },
            process.env.JWT_SECRET,
            {
                expiresIn: "15m"
            }
        )

        const newRefreshToken = jwt.sign(
            {
                id: user._id,
            },
            process.env.JWT_REFRESH_SECRET,
            {
                expiresIn: "7d"
            }
        )

        user.refreshToken = newRefreshToken;
        await user.save()

        res.cookie("accessToken", newAccessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 15 * 60 * 1000
        })

        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000
        })

        

        // res.status(200).json({
        //     accessToken: newAccessToken
        // })

        res.status(200).json({
            message: "Access token refreshed"
        })
        
    } catch(err){
        res.status(403).json({
            message: "Invalid or expired refresh token"
        })
    }
})



app.get("/profile", authMiddleware, async function(req, res){
    res.status(200).json({
        user: req.user
    })
})



app.listen(3000)
