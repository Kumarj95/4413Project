// import the user Data Access Object in order to make data calls to the user DB
import UserDAO from "../dao/UserDAO.js";

// import the visit Data Access Object in order to make data calls to the user DB
import VisitDAO from "../dao/visitDAO.js";

// import the config file to redirect initial post method
import config from "../config/config.js";

// set port based on config file
const port = config.PORT;

// This function will check whether a cookie exists on the user entering the site, and if not, then send new one
const enterSite = async (req, res) => {
    const cookies = req.cookies;

    var today = new Date();
    var dd = String(today.getDate()).padStart(2, '0');
    var mm = String(today.getMonth() + 1).padStart(2, '0'); //January is 0!
    var yyyy = today.getFullYear();
    today = mm + '/' + dd + '/' + yyyy;
    const visit = await VisitDAO.getVisit(today, req.ip, "Home Page")
    if (visit.length === 0) {
        console.log("made it in")
        const newVisitInfo = {
            date: today,
            ipAddress: req.ip,
            visitType: "Home Page"
        };
        await VisitDAO.createVisit(newVisitInfo)
    }

    // if there is no cookie, assign one and create new user object in DB, assigning random user values for their visit.
    // once the cookie has expired, then delete user from DB??
    if (!cookies?.jwt) {
        // update to properly redirect without hard setting values
        
        res.redirect(
            307,
            "http" + (req.socket.encrypted ? "s" : "") + "://" + req.headers.host + "/api/user/addUser?createCheck=false"
        );
    } 
    else {
        
        const refreshToken = cookies.jwt;
        
        const user = await UserDAO.getUser("refreshToken", refreshToken);

        if (!user) {
            console.log("User not found, redirect to login page.");
            return res.sendStatus(401); //Unauthorized
        }

        if (user.type == "user") {
            // do nothing 
            res.status(201).json({message: 'user found, but will not persist until logged in'});
        } 
        else {
            res.status(201).json({
                success: `User found, persist cart through getCart call.`,
            });
        }
    }
}

export default {enterSite}