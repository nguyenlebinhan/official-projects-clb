import userModels from '../models/userModels.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import validator from 'validator';

//login user
const loginUser= async (req,res) => {
    const{email,password}= req.body;
    try{
        const user= await userModels.findOne({email})

        if(!user){
            return res.json({success:false,message:"User not found"})
        }
        
        const isMatch= await bcrypt.compare(password,user.password)

        if(!isMatch){
            return res.json({success:false,message:"Invalid credentials"})
        }

        const token= createToken(user._id);

        res.json({success:true,token})

    }catch(error){

        console.log(error);

        res.json({success:false,message:"Error"})
    }
}

//create token
const createToken= (id) => {
    return jwt.sign({id},process.env.JWT_SECRET,{
        expiresIn:3*24*60*60
    });
}
//register user
const registerUser= async (req,res) => {
    const {username,email,password} = req.body;
    try{
        //check is user already exists
        const existsEmail= await userModels.findOne({email});
        if(existsEmail){
            return res.json({success:false,message:"User already exists"})
        }

        //validate email format & strong password
        if(!validator.isEmail(email)){
            return res.json({success:false,message:"Please enter a valid email"})
        }

        if(password.length<8){
            return res.json({success:false,message:"Please enter a strong password"})            
        }

        // hashing user password
        const salt= await bcrypt.genSalt(10)
        const hashedPassword= await bcrypt.hash(password,salt)

        //create new user with new hashed password
        const newUser= new userModels({
            username,
            email,
            password:hashedPassword
        })

        //save new user to db
        const user = await newUser.save()
        const token= createToken(user._id)
        res.json({success:true,token})
    }catch(error){
        console.log(error);
        res.json({success:false,message:"Error"})

    }
}


export {loginUser, registerUser}
