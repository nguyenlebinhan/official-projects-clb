import express from 'express';
import { loginUser,registerUser } from '../controllers/userController.js';
import verifyToken from '../middleware/auth.js';

const userRouter = express.Router()


userRouter.post("/register", registerUser)
userRouter.post("/login",loginUser)

//protected route
userRouter.get("/protected",verifyToken,(req,res)=>{
    res.json({success:true,message:'This is a protected route'})
})
export default userRouter;