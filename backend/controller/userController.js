// import the user Data Access Object in order to make data calls to the user DB
import UserDAO from "../dao/UserDAO.js";

// import the bcrypt package for encrypting the jwt tokens
import bcrypt from "bcrypt";

// import the jason web token package to create these tokens
import jwt from "jsonwebtoken";

// import random string package for create fake user
import randomstring from "randomstring";

// This function will get the users information.
const getUser = async (req, res) => {
    // get cookie from request
    const cookies = req.cookies;

    // if no cookie, then send back 204 no content error
    if (!cookies?.jwt) return res.sendStatus(204); //No content

    // get refreshtoken from jwt cookie
    const refreshToken = cookies.jwt;

    // find the user attached to the refresh token
    const foundUser = await UserDAO.getUser( "refreshToken", refreshToken)

    // if user is not found, then clear cookie and send no-content back
    if (!foundUser) {
        res.clearCookie('jwt', { httpOnly: true, secure: true, sameSite: 'None'});
        return res.sendStatus(204);
    }

    res.json(foundUser);
};

// This function will create a user. There are two ways this works:
// 1 - if the user enters the main website not logged in, we will create a fake user
// that will allow their cart to be persisted. The information for name, email, pwd 
// will be fake in the DB, thus not compromising securtity.
// 2 - if the user is actually registering an account, then the normal process will
// occur.
const createNewUser = async (req, res) => {

    // get variable createCheck from query parameter if this method was called 
    // from the api/home, which creates a fake user in the db
    const createCheck = req.query.createCheck;

    // create basic info params
    let Name = "";
    let pwd = "";
    let Email = "";

    // if api call came from api/home, fill basic info with random values
    if (createCheck == "false") {
        Name = randomstring.generate(10);
        pwd = randomstring.generate(10);
        Email = randomstring.generate(10);
    } 
    // if api call came directly from registration page, get actual info
    else {
        Name = req.body.Name;
        pwd = req.body.Password;
        Email = req.body.Username;
    }

    // if no name, email, or password information provided, generate error
    if (!Name || !Email || !pwd)
        return res
            .status(400)
            .json({ message: "Name, Email and Password are required." });

    // check for duplicate usernames in the db, is so, send 409 conflict
    const duplicate = await UserDAO.getUser("email", Email);
    if (duplicate) return res.sendStatus(409); //Conflict

    // try and create a user in the DB.
    try {
        
        //encrypt the password
        const hashedPwd = await bcrypt.hash(pwd, 10);

        // get cookie from request
        const cookies = req.cookies;

        // if no cookies or api call from api/home, create new user in DB that is a browser
        if (createCheck == "false" || !cookies?.jwt) {
            
            // create user data
            const newUser = {
                name: Name,
                password: hashedPwd,
                email: Email,
            };

            // create refresh token 
            const refreshToken = jwt.sign(
                { name: Name },
                process.env.REFRESH_TOKEN_SECRET,
                { expiresIn: "1d" }
            );

            // assign refresh token to the user data
            newUser.refreshToken = refreshToken;

            // set the user data type to browser
            newUser.type = "browser";

            // persist new user in db
            await UserDAO.createUser(newUser);

            // create cookie with jwt token and below params
            res.cookie("jwt", refreshToken, {
                httpOnly: true,
                sameSite: "Strict",
                maxAge: 12 * 60 * 60 * 1000,
            });
        } 
        // if this is an actual user registration, they will already have an enrty in the DB
        // we will override thie entry and fill it in with the accurate basic user info
        else {

            // get the refresh token for the user
            const refreshToken = cookies.jwt;

            // find the duplicate user in the DB
            const duplicateUser = await UserDAO.getUser(
                "refreshToken",
                refreshToken
            );

            // if no duplicate user in DB, something suspicious is happening, send 401 error
            if (!duplicateUser) return res.sendStatus(401); //Unauthorized

            // update duplicateUsers name
            duplicateUser.name = Name;
    
            // update users password
            duplicateUser.password = hashedPwd;
            
            // update users email
            duplicateUser.email = Email;

            // update users type to user
            duplicateUser.type = "user";

            // persist user in the backend
            await UserDAO.updateUser(duplicateUser);

        }

        res.status(201).json({ success: `New user ${Email} created!` });
    } catch (err) {
        console.log(err);
        res.send(err);
    }
};

// This function will log in a user as long as they have entered their correct email
// and password
const loginUser = async (req, res) => {

    // get the password from the request body
    const pwd = req.body.Password;
    
    // get the email from the request body
    const user = req.body.Username;

    // if no username or password provided, then reject
    if (!user || !pwd)
        return res
            .status(400)
            .json({ message: "Username and password are required." });

    // find user in the database for verification purposes
    const foundUser = await UserDAO.getUser("email", user);

    // if no user, then unauthorized to login
    if (!foundUser) return res.sendStatus(401); //Unauthorized

    // evaluate password by encrpyting provided password and comparing
    const match = await bcrypt.compare(pwd, foundUser.password);
    
    // if the passwords match, send access token and log user in
    if (match) {

        // create JWT access and new refresh token for user now that they are logged in
        const accessToken = jwt.sign(
            {
                UserInfo: {
                    name: foundUser.name,
                    email: foundUser.email,
                    roles: foundUser.type,
                },
            },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: "30s" }
        );

        const refreshToken = jwt.sign(
            { name: foundUser.name },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: "1d" }
        );
        
        // Saving refreshToken with current user
        foundUser.refreshToken = refreshToken;

        // update user in backend
        await UserDAO.updateUser(foundUser);

        // Creates Cookie with refresh token
        res.cookie("jwt", refreshToken, {
            httpOnly: true,
            sameSite: "Strict",
            maxAge: 24 * 60 * 60 * 1000,
        });

        // Send access token to front end
        res.json({ user: accessToken });

    } 
    else {
        res.sendStatus(401);
    }
};

// this function will allow a logged in user to request a new refresh token
// this can only be called once the user places an order, which we 
// have guarded in the front end from being able to be reached unless
// you have logged in
const handleRefreshToken = async (req, res) => {

    // get coookie from request
    const cookies = req.cookies;

    // if no cookie, unauthorized
    if (!cookies?.jwt) return res.sendStatus(401);

    // get refresh token from cookie
    const refreshToken = cookies.jwt;

    // find user in database based on refresh token
    const foundUser = await UserDAO.getUser("refreshToken", refreshToken);

    // if no user, forbidden access
    if (!foundUser) return res.sendStatus(403); //Forbidden is no user in DB

    // if the user is in fact a browser, and they have gotten past security, they will not be allowed.
    if (foundUser.type == "browser") return res.sendStatus(401); // if user is type browser, they don't get a new access token

    // evaluate jwt refresh token to make sure it is legit. If so, then send new access token.
    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        (err, decoded) => {
            if (err || foundUser.name !== decoded.name)
                return res.sendStatus(403);
            //const roles = Object.values(foundUser.roles);
            const accessToken = jwt.sign(
                {
                    UserInfo: {
                        name: foundUser.name,
                        email: foundUser.email,
                        roles: foundUser.type,
                    },
                },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: "30s" }
            );
            res.json({ user: accessToken });
        }
    );
};

// This function will allow the user to log out of their account, which will in turn 
// remove the refresh token associated with account, and not allowing us to
// persist any information for the user in the front end
const handleLogout = async (req, res) => {

    // get coookie from request
    const cookies = req.cookies;

    // if no cookie, unauthorized
    if (!cookies?.jwt) return res.sendStatus(401);

    // get refresh token from cookie
    const refreshToken = cookies.jwt;

    // find user in database based on refresh token
    const foundUser = await UserDAO.getUser("refreshToken", refreshToken);

    // if no user, forbidden access
    if (!foundUser) return res.sendStatus(403); //Forbidden is no user in DB

    // Delete refreshToken in db
    foundUser.refreshToken = "";

    // update user to have no refresh token
    await UserDAO.updateUser(foundUser);

    // update cookie in front end to be removed.
    res.clearCookie("jwt", { httpOnly: true, sameSite: "Strict" });

    // send 204 status confirming logout
    res.sendStatus(204);
};

export default {
    getUser,
    createNewUser,
    loginUser,
    handleRefreshToken,
    handleLogout,
};
