import express from 'express'
import Cart from '../models/cartModel.js'

const getCart = async(req, res) => {
    if (!req?.query?.email) return res.status(400).json({ "message": 'Email required' });
    const owner = req.user._id
    const user = await Cart.findOne({ owner }).exec();
    if(!cart) {
        return res.status(204).json({ 'message': `User ID ${req.params.id} not found` });
    }
    res.json(cart)
}

export default {getCart}

/*
const createCart = async(req, res) => {
    const owner = req.user._id;


}*/