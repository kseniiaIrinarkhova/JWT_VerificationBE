const jwt = require('jsonwebtoken');

module.exports = function(req,res,next){
//get token from the header
    const token = req.header('x-auth-token');

    //check if there is not a token
    if(!token){
        return res.status(401).json({errors :[{message: "No token, auth denied"}]})
    }
    //verify if token is valid
    try {
        const decoded = jwt.verify(token, process.env.jwtToken);

        req.user = decoded.user
        next();
    } catch (err) {
        console.log(err)
        return res.status(401).json({ errors: [{...err}, { message: "Token is not valid" }] })
    }
}