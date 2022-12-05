import express from 'express'
import User from '../models/userModel.js'
import Cart from '../models/userModel.js'
import bcrypt from 'bcrypt'
import randomstring from 'randomstring'
import jwt from 'jsonwebtoken'

const getUser = async(req, res) => {
    if (!req?.query?.email) return res.status(400).json({ "message": 'Email required' });
    const user = await User.findOne({email: req.query.email}).exec();
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
    const duplicate = await User.findOne({ email: Email }).exec();
    if (duplicate) return res.sendStatus(409); //Conflict 

    try 
    {
        //encrypt the password
        const hashedPwd = await bcrypt.hash(pwd, 10);
        
        if (createCheck == "false") {
            
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

            await User.create(newUser);

            res.cookie('jwt', refreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });
        }
        else {

            const cookies = req.cookies;
        
            if (!cookies?.jwt) return res.sendStatus(401);

            const refreshToken = cookies.jwt;

            const duplicateUser = await User.findOne({ refreshToken }).exec();

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

            await duplicateUser.save();

            res.cookie('jwt', newRefreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });

        }

        res.status(201).json({ 'success': `New user ${Email} created!` });

    } catch (err) 
    {
        console.log(err);
        res.send(err);
    }
}

export default {getUser, createNewUser}