import express from 'express'
import Cart from '../models/cartModel.js'

const getCart = async function(owner) {
    const cart = await Cart.findOne({ _id: owner }).exec();
    return cart;
}


const createCart = async function(cartData) {
    await Cart.create(cartData);
}



export default {getCart, createCart}