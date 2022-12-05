import express from 'express'
import dotenv from'dotenv'
import connectDB from './config/db.js'
import userRouter from "./routes/userRoute.js"
import homeRouter from "./routes/homeRoute.js"
import cartRouter from "./routes/cartRoute.js"
import cookieparser from 'cookie-parser'
import JWTVerify from "./middleware/JWTVerify.js"
import bcrypt from 'bcrypt'
import bcryptjs from 'bcryptjs'
import https from 'https'
import fs from 'fs'
import {notFound, errorHandler} from './middleware/errorMiddleware.js'
dotenv.config()
connectDB()
const app=express()

app.use(express.urlencoded({extended:false}))
app.use(express.json())
app.use(cookieparser())
app.use("/api/user",userRouter)
app.use("/api/cart",cartRouter)
app.use("/api/home",homeRouter)
app.use(notFound)
app.use(errorHandler)
app.use(JWTVerify.verifyJWT)
const PORT=process.env.PORT || 5000

app.listen(PORT, console.log(`Server Running in ${process.env.NODE_ENV} mode on port ${PORT}`))

// remove this when merging, store locally until we are ready to use in final product.
const server = https.createServer(
    {
        key: fs.readFileSync("./backend/key.pem"),
        cert: fs.readFileSync("./backend/cert.pem")

    },app
).listen(5443, (req, res) => console.log(`Server running on port ${5443}`));

//server
