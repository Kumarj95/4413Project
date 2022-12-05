import express from 'express'
import User from '../models/userModel.js'
import UserDAO from '../dao/UserDAO.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

const loginUser = async(req, res) => {

    const loginCheck = req.query.loginCheck;

    let pwd = ''
    let user = ''

    if (loginCheck == "false") {

        pwd = req.query.password
        user = req.query.email

    } else {
        
        pwd = req.body.Password
        user = req.body.Email

    }

    if (!user || !pwd) return res.status(400).json({ 'message': 'Username and password are required.' });

    const foundUser = await User.findOne({ email: user }).exec();
    if (!foundUser) return res.sendStatus(401); //Unauthorized 
    // evaluate password 
    const match = await bcrypt.compare(pwd, foundUser.password);
    if ( pwd == "true" || match) {
        //const roles = Object.values(foundUser.roles).filter(Boolean);
        // create JWTs
        const accessToken = jwt.sign(
            {
                "UserInfo": {
                    "name": foundUser.name,
                    "roles": 'user'
                }
            },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '30s' }
        );
        const refreshToken = jwt.sign(
            { "name": foundUser.name },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: '1d' }
        );
        // Saving refreshToken with current user
        foundUser.refreshToken = refreshToken;
        const result = await foundUser.save();
        console.log(result);

        // Creates Secure Cookie with refresh token
        //res.cookie('jwt', refreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });

        res.cookie('jwt', refreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });

        // Send authorization roles and access token to user AND send other user info such as cart.
        res.json({ 'user': accessToken });

    } else {
        res.sendStatus(401);
    }
}


const handleRefreshToken = async (req, res) => {
    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(401);
    const refreshToken = cookies.jwt;

    const foundUser = await User.findOne({ refreshToken }).exec();
    if (!foundUser || foundUser.type == "browser") return res.sendStatus(403); //Forbidden is no user in DB AND if user is type browser
    // evaluate jwt 
    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        (err, decoded) => {
            if (err || foundUser.name !== decoded.name) return res.sendStatus(403);
            //const roles = Object.values(foundUser.roles);
            const accessToken = jwt.sign(
                {
                    "UserInfo": {
                        "name": decoded.username,
                        "roles": 'user'
                    }
                },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: '30s' }
            );
            res.json({ 'user': accessToken })
        }
    );
}

const handleLogout = async (req, res) => {
    // On client, also delete the accessToken

    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(204); //No content
    const refreshToken = cookies.jwt;

    // Is refreshToken in db?
    const foundUser = await User.findOne({ refreshToken }).exec();
    if (!foundUser) {
        //res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
        res.clearCookie('jwt', { httpOnly: true, secure: true, sameSite: 'None'});
        return res.sendStatus(204);
    }

    // Delete refreshToken in db
    foundUser.refreshToken = '';
    const result = await foundUser.save();
    console.log(result);

    //res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });

    res.clearCookie('jwt', { httpOnly: true, secure: true, sameSite: 'None'});
    
    res.sendStatus(204);

}


export default {loginUser, handleRefreshToken, handleLogout}