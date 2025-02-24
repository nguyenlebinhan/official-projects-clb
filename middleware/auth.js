const jwt=require('jsonwebtoken');

const verifyToken=(req,res,next)=>{
    const token=req.header['authorization'];
    if(!token){
        return res.json({success:false,message:"Access denied"})
    }
    try{
        const verified= jwt.verify(token,process.env.JWT_SECRET);
        req.user=verified;
        next();
    }catch(error){
        console.log(error);
        res.json({success:false,message:"Invalid token"})
    }
};

export default verifyToken;