import express from 'express'
import UserDAO from '../dao/UserDAO.js'
import UserCtrl from '../controller/userController.js'

// User Route to access user data, log users in, sign users up etc etc
const router= express.Router()

router.get('/getUser', UserCtrl.getUser)

router.post('/addUser', UserCtrl.createNewUser)

router.post('/login', UserCtrl.loginUser)

router.get('/refresh', UserCtrl.handleRefreshToken)

router.get('/logout', UserCtrl.handleLogout)
    
export default router;
