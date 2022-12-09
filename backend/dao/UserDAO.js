import express from 'express'
import User from '../models/userModel.js'
import Cart from '../models/userModel.js'
import bcrypt from 'bcrypt'
import randomstring from 'randomstring'
import jwt from 'jsonwebtoken'

const getUser = async function(valType, userVal) {

    let user;
    if (valType == "email") {
        user = await User.findOne({email: userVal}).exec();
    }
    else if (valType == "refreshToken") {
        user = await User.findOne({refreshToken: userVal}).exec();
    }
    else if (valType == "userId") {
        user = await User.findOne({_id: userVal}).exec();
    }

    return user;

}

const createUser = async(newUser) => {
    await User.create(newUser);
}

const updateUser = async(updatedUser) => {
    await updatedUser.save();
}

const deleteUser = async(valType, userVal) => {
    let user;
    if (valType == "email") {
        user = await User.deleteOne({email: userVal}).exec();
    }
    else if (valType == "refreshToken") {
        user = await User.deleteOne({refreshToken: userVal}).exec();
    }
    else if (valType == "userId") {
        user = await User.deleteOne({_id: userVal}).exec();
    }
}

export default {getUser, createUser, updateUser, deleteUser}