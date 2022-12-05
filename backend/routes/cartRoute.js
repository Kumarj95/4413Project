import express from 'express'
import cartDAO from '../dao/cartDAO.js'
import cartCtrl from '../controller/cartController.js'

// User Route to access user data, log users in, sign users up etc etc
const router= express.Router()


router.get('/getCart', cartDAO.getCart)

router.post('/addCart', cartCtrl.addCart)

router.delete('/deleteCartItem', cartCtrl.deleteCartItem)

router.delete('/deleteCart', cartCtrl.deleteCart)

//router.get('/logout', UserCtrl.handleLogout)
    
export default router;