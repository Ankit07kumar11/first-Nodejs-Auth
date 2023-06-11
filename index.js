const express=require("express");
const bodyParser=require("body-parser")
const mongoose=require("mongoose");
const cookieParser=require("cookie-parser")
const jwt =require("jsonwebtoken");
const bcrypt =require("bcrypt");

const app=express();

app.use(bodyParser.urlencoded({extended:true}))
app.use(express.json());
app.use(cookieParser());

mongoose.connect("mongodb://127.0.0.1:27017/auth",{useNewUrlParser:true,useUnifiedTopology:true}).then(()=>{
    console.log("Database Connected");
}).catch((err)=>{console.log(err)})

const userSchema=new mongoose.Schema({
    name:String,
    email:String,
    password:String
});

const User=new mongoose.model("User",userSchema)

app.set("view engine","ejs");

const isAuthenticated=async(req,res,next)=>{
    const {token}=req.cookies;
    if(token){
        const decode=jwt.verify(token,"abcdefghijk");
        // console.log(decode)
        
        req.user=await User.findById(decode._id)
        next()
    }
    else{
        res.redirect("/login")
        
    }
}


app.get("/",isAuthenticated,(req,res)=>{
    
    res.render("logout",{name:req.user.name})
})

app.get("/register",(req,res)=>{
    
    res.render("register")
})

app.get("/login",(req,res)=>{
    
    res.render("login")
})

app.post("/login",async(req,res)=>{
    const {email,password}=req.body;
    let user=await User.findOne({email});

    if(!user){
       return res.redirect("/register")
    }

    const isMatch= await bcrypt.compare(password,user.password)

    if(!isMatch) return res.render("login",{email,message:"incorrect Password"})
    else{
        const token=jwt.sign({_id:user._id},"abcdefghijk")

    res.cookie("token",token,{httpOnly:true,expires:new Date(Date.now()+60*1000)});
    res.redirect("/")
    }
})

app.post("/register",async(req,res)=>{
    
    const {name,email,password}=req.body;
    let user=await User.findOne({email})
    if(user){
        return res.redirect("/login")
    }
    
    const hashedPassword=await bcrypt.hash(password,10);
    
    user= await User.create({
        name,
         email,
         password:hashedPassword
    })

    const token=jwt.sign({_id:user._id},"abcdefghijk")

    res.cookie("token",token,{httpOnly:true,expires:new Date(Date.now()+60*1000)});
    res.redirect("/")
})

app.get("/logout",(req,res)=>{
    res.cookie("token","null",{httpOnly:false,expires:new Date(Date.now())});
    res.redirect("/")
})


app.listen(5000,()=>{
    console.log("Server is running at http://localhost:5000")
})