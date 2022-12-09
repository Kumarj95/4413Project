import express from 'express'
import User from '../models/userModel.js'
import UserDAO from '../dao/UserDAO.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import randomstring from 'randomstring'

const getUser = async(req, res) => {
    if (!req?.query?.email) return res.status(400).json({ "message": 'Email required' });
    const user = await UserDAO.getUser("email", req.query.email);
    if(!user) {
        return res.status(204).json({ 'message': `User ID ${req.params.id} not found` });
    }
    res.json(user)
}

const createNewUser = async(req, res) => {

    const createCheck = req.query.createCheck;

    let Name = ''
    let pwd = ''
    let Email = ''

    if (createCheck == "false") {
        Name = randomstring.generate(10)
        pwd = randomstring.generate(10)
        Email = randomstring.generate(10)
    }
    else {
        Name = req.body.Name
        pwd = req.body.Password
        Email = req.body.Email
    }

    if (!Name || !Email || !pwd) return res.status(400).json({ 'message': 'Name, Email and Password are required.' });

    // check for duplicate usernames in the db
    const duplicate = await UserDAO.getUser("email", Email);
    if (duplicate) return res.sendStatus(409); //Conflict 

    try 
    {
        //encrypt the password
        const hashedPwd = await bcrypt.hash(pwd, 10);

        const cookies = req.cookies;
        
        if (createCheck == "false" || !cookies?.jwt) {
            
            const newUser= {
                name:Name,
                password:hashedPwd,
                email:Email,
            }

            const refreshToken = jwt.sign(
                { "name": Name },
                process.env.REFRESH_TOKEN_SECRET,
                { expiresIn: '1d' }
            );
            
            newUser.refreshToken = refreshToken;
            
            newUser.type="browser"

            await UserDAO.createUser(newUser);

            res.cookie('jwt', refreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });
        }
        else {

            const refreshToken = cookies.jwt;

            const duplicateUser = await UserDAO.getUser("refreshToken", refreshToken);

            if (!duplicateUser) return res.sendStatus(401); //Unauthorized

            res.clearCookie('jwt', { httpOnly: true, secure: true, sameSite: 'None'});
            
            duplicateUser.name = Name;

            duplicateUser.password = hashedPwd;

            duplicateUser.email = Email;

            duplicateUser.type = "user"

            const newRefreshToken = jwt.sign(
                { "name": Name },
                process.env.REFRESH_TOKEN_SECRET,
                { expiresIn: '1d' }
            );
            
            duplicateUser.refreshToken = newRefreshToken;

            await UserDAO.updateUser(duplicateUser);

            res.cookie('jwt', newRefreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });

        }

        res.status(201).json({ 'success': `New user ${Email} created!` });

    } catch (err) 
    {
        console.log(err);
        res.send(err);
    }
}

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

    const foundUser = await UserDAO.getUser("email", user);
    //const foundUser = await User.findOne({ email: user }).exec();
    if (!foundUser) return res.sendStatus(401); //Unauthorized 
    // evaluate password 
    const match = await bcrypt.compare(pwd, foundUser.password);
    if ( pwd == "true" || match) {
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

        await UserDAO.updateUser(foundUser);

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

    const foundUser = await UserDAO.getUser("refreshToken", refreshToken);

    //const foundUser = await User.findOne({ refreshToken }).exec();
    if (!foundUser) return res.sendStatus(403); //Forbidden is no user in DB
    
    if (foundUser.type == "browser") return res.sendStatus(401) // if user is type browser, they don't get a new access token
    
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
    const foundUser = await UserDAO.getUser("refreshToken", refreshToken);
    //const foundUser = await User.findOne({ refreshToken }).exec();
    if (!foundUser) {
        //res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
        res.clearCookie('jwt', { httpOnly: true, secure: true, sameSite: 'None'});
        return res.sendStatus(204);
    }

    // Delete refreshToken in db
    foundUser.refreshToken = '';

    await UserDAO.updateUser(foundUser);

    //res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });

    res.clearCookie('jwt', { httpOnly: true, secure: true, sameSite: 'None'});
    
    res.sendStatus(204);

}


export default {getUser, createNewUser, loginUser, handleRefreshToken, handleLogout}