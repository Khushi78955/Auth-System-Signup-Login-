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
const GitHubStrategy = require("passport-github2").Strategy;
const session = require("express-session");
const rateLimit = require("express-rate-limit")
const crypto = require("crypto")
const nodemailer = require("nodemailer")

 
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



mongoose.connect(process.env.MONGO_URL)
.then(() => console.log("MongoDB connected"))
.catch((err) => console.log(err))


const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    refreshToken: String, 
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    otp: String, 
    otpExpires: Date,
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
                password: "",
                isVerified: true
            })
        }
        return done(null, user);
    } catch(err){
        return done(err, null)
    }
}))



passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "/auth/github/callback"
},
async function(accessToken, refreshToken, profile, done){
    try{
        const email = profile.emails?.[0]?.value || `${profile.username}@github.com`;

        let user = await User.findOne({
            email
        })
        if(!user){
            user = await User.create({
                name: profile.username,
                email,
                password: "",
                isVerified: true
            })
        }
        return done(null, user)
    } catch(err){
        return done(err, null)
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


const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
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
        return res.status(401).json({
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

const otpLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 3,
    message: {
        message: "Too many OTP requests. Try again later"
    }
})



app.get("/", function(req, res){
    return res.json({
        message: "Auth system"
    })
}) 



app.get("/admin", authMiddleware, adminMiddleware, function(req, res){
    return res.status(200).json({
        message: "welcome admin"
    })
})



app.get("/auth/google",
    passport.authenticate("google", {
        scope: ["profile", "email"]
    })
)

app.get("/auth/github", 
    passport.authenticate("github", {
        scope: ["user:email"]
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
        return res.status(200).json({
            message: "Google login successful"
        })


    }
)


app.get("/auth/github/callback",
    passport.authenticate("github", {
        failureMessage: true
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
        return res.status(200).json({
            message: "Github login successful"
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
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Verify your email",
            text: `Click here to verify your email: ${verificationLink}`
        })

        return res.status(201).json({
            message: "Signup successful. Please verify your email.",
            user: {
                id: response._id,
                name: response.name,
                email: response.email
            }
        })
    } catch(err){
        return res.status(500).json({
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
        if(user.isVerified){
            return res.status(400).json({
                message: "User already verified"
            })
        }

        user.isVerified = true
        user.verificationToken = ""

        user.otp = ""
        user.otpExpires = null
        
        await user.save()

        return res.status(200).json({
            message: "email verified successfully"
        })
    } catch(err){
        return res.status(500).json({
            message: "Something went wrong"
        })
    }
})



app.post("/send-otp", otpLimiter, async function(req, res){
    try{
        const { email } = req.body;
        const user = await User.findOne({
            email
        })

        if(!user){
            return res.status(404).json({
                message: "User not found"
            })
        }

        if(user.isVerified){
            return res.status(400).json({
                message: "User already verified"
            })
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedOtp = await bcrypt.hash(otp, 10);
        user.otp = hashedOtp;
        user.otpExpires = Date.now() + 5 * 60 * 1000;

        await user.save();

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Your OTP code",
            text: `Your OTP is ${otp}`
        })

        return res.status(200).json({
            message: "OTP sent successfully"
        })
    } catch(err){
        return res.status(500).json({
            message: "Something went wrong"
        })
    }
    


})



app.post("/verify-otp", async function(req, res){
    try{
        const { email, otp } = req.body;
        const user = await User.findOne({
            email
        })
        if(!user){
            return res.status(404).json({
                message: "User not found"
            })
        }
        if(!user.otp){
            return res.status(400).json({
                message: "No OTP found"
            })
        }

        if(!user.otpExpires){
            return res.status(400).json({
                message: "No OTP request found"
            })
        }

        if(user.otpExpires < Date.now()){
            return res.status(400).json({
                message: "OTP expired"
            })
        }

        const isOtpValid = await bcrypt.compare(otp, user.otp);
        if(!isOtpValid){
            return res.status(400).json({
                message: "Invalid otp"
            })
        }
        

        user.isVerified = true;
        user.verificationToken = ""

        user.otp = "";
        user.otpExpires = null;
        
        await user.save();

        return res.status(200).json({
            message: "OTP verified successfully"
        })
    } catch(err){
        return res.status(500).json({
            message: "Something went wrong"
        })
    }
})



app.post("/resend-otp", otpLimiter, async function(req, res){
    try{
        const { email } = req.body;
        const user = await User.findOne({
            email
        })

        if(!user){
            return res.status(404).json({
                message: "User not found"
            })
        }

        if(user.isVerified){
            return res.status(400).json({
                message: "User already verified"
            })
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        const hashedOtp = await bcrypt.hash(otp, 10);
        user.otp = hashedOtp;
        user.otpExpires = Date.now() + 5 * 60 * 1000;

        await user.save();
        
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Your OTP code",
            text: `Your OTP is ${otp}`
        })

        return res.status(200).json({
            message: "OTP sent successfully"
        })
    } catch(err){
        return res.status(500).json({
            message: "Something went wrong"
        })
    }
    
})



app.post("/forgot-password", async function(req, res){
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
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Reset your password",
            text: `Click here to reset your password: ${resetLink}`
        })

        return res.status(200).json({
            message: "Password reset link generated"
        })
    } catch(err){
        return res.status(500).json({
            message: "Something went wrong"
        })
    }
    


})



app.post("/reset-password/:token", async function(req, res){
    try{
        const token = req.params.token;
        const { password } = req.body;
        const passwordSchema = z.string()
            .min(6)
            .regex(/[A-Z]/, "Must contain one uppercase letter")
            .regex(/[a-z]/, "Must contain one lowercase letter")
            .regex(/[0-9]/, "Must contain one number")
            .regex(/[^A-Za-z0-9]/, "Must contain one special character")

        const result = passwordSchema.safeParse(password);

        if(!result.success){
            return res.status(400).json({
                message: "Invalid password format"
            })
        }
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

        if(!user.password){
            return res.status(400).json({
                message: "Please login with Google or GitHub"
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


        return res.status(200).json({
            message: "Login successful"
        })
    } catch(err){
        return res.status(500).json({
            message: "Something went wrong"
        })

    }
})



app.post("/logout", async function(req, res){
    try{
        const refreshToken = req.cookies.refreshToken;

        if(!refreshToken){
            return res.status(400).json({
                message: "No refresh token found"
            })
        }

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

        return res.status(200).json({
            message: "Logout successful"
        })

    } catch(err){
        return res.status(500).json({
            message: "Something went wrong"
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

        return res.status(200).json({
            message: "Access token refreshed"
        })
        
    } catch(err){
        return res.status(403).json({
            message: "Invalid or expired refresh token"
        })
    }
})



app.get("/profile", authMiddleware, async function(req, res){
    return res.status(200).json({
        user: req.user
    })
})



app.get("/send-mail", async function(req, res){
    try{
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: process.env.EMAIL_USER,
            subject: "Test Email",
            text: "Nodemailer is working"
        })

        return res.status(200).json({
            message: "Email sent successfully"
        })
    } catch(err){
        console.log(err);
        return res.status(500).json({
            message: "Email failed"
        })
    }
    
})


app.use((req, res) => {
    return res.status(404).json({
        message: "Route not found"
    })

})


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
})

