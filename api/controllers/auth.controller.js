import User from "../models/user.model.js";
import bcryptjs from 'bcryptjs';
import { errorHandler } from "../utils/error.js";
import jwt from 'jsonwebtoken';
export const signup = async (req,res,next)=>{
  
    const {username, email,password} = req.body; 
    const hashedPassword = bcryptjs.hashSync(password,10);
    const newUser = new User({ username, email, password: hashedPassword});
    try{
        await newUser.save();
        res.status(201).json("User Created successfully!");

    } catch(error){
       next(error);
    }
 
};

export const signin = async (req,res,next)=>{
 //get data from req.body mails and password 
 const {email , password} = req.body;

 try{
    //check if email exist than only check password 
    const validUser = await User.findOne({email}) ; 
    if(!validUser) return next(errorHandler(404,'User not found!'));
    //else mail exist now see password -> compare user password written with password coming from db
    const validPassword = bcryptjs.compareSync(password, validUser.password);
    if (!validPassword) return next(errorHandler(401, 'Wrong credentials!'));

    //now,if both mail password correct authenticate the user -> using add cookie inside a browser 
    //for all user inside db unique id assign using that for creating token and authenticating user
    const token = jwt.sign({ id: validUser._id }, process.env.JWT_SECRET);

    //we don't want to see password of the user even hashed one -> destructure the password i.e remove from rest information 
    //now no woory of password leak problem
    const { password: pass, ...rest } = validUser._doc;

      //now,save the token as cookies 
    res
      .cookie('access_token', token, { httpOnly: true }) //httpOnly:true makes sure no 3rd party has cookie access
      .status(200)
      .json(rest);
 }catch(error){
    next(error);
 }
};
