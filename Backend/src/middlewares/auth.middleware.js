import jwt from "jsonwebtoken"
import User from "../models/user.model.js"
import { login } from "../controller/auth.controller.js"

export const protectRoute = async(req,res,next) =>{
    try {
        const token  = req.cookies.jwt

        if(!token) return res.status(401).json({message:"Unauthorized - No token Provided"})
        
        const decodedCookie = jwt.verify(token , process.env.JWT_SECRET)

        if(!decodedCookie) return res.status(401).json({message:"Unauthorized - Invalid token"})

        const user = await User.findById(decodedCookie.userId).select("-password")

        if(!user) return res.status(404).json({message:"User not found"})

        req.user  = user;

        next()

    } catch (error) {
        console.log("Error in protectRoute" , error.message);
        res.status(500).json({message:"Internam server error"})
        
    }
}