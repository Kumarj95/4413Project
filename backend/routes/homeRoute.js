import express from 'express'
import User from '../models/userModel.js'
import UserDAO from '../dao/UserDAO.js'
import e from 'express'

// User Route to access user data, log users in, sign users up etc etc
const router= express.Router()

// This should check and see if refresh token already exists, if so, try and find a 
// user with it in DB. 
router.post('/', async(req,res)=>{
    const cookies = req.cookies;

    // if there is no cookie, assign one and create new user object in DB, assigning random user values for their visit.
    // once the cookie has expired, then delete user from DB??
    if (!cookies?.jwt) {
        // update to properly redirect without hard setting values
        res.redirect(307, 'https://localhost:5443/api/user/addUser?createCheck=false');

    }
    else {

        const refreshToken = cookies.jwt
        
        const user = await UserDAO.getUser("refreshToken", refreshToken);

        if (!user) return res.sendStatus(401); //Unauthorized 

        // if user is type user, login and send through cart. otherwise, send cart.

        if (user.type == "user") {
            
            res.clearCookie('jwt', { httpOnly: true, secure: true, sameSite: 'None'});

            res.redirect(307, 'https://localhost:5443/api/user/login?loginCheck=false&email=' + user.email + '&password=true');

        }
        else {
            
            res.status(201).json({ 'success': `User found, persist cart through getCart call.` });

        }

    }
})
    
export default router;
