const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const User = require('../../models/User')
require('dotenv').config();

const router = express.Router();

// @route:   GET api/users
// @desc:    Test route
// @access:  Public
router.get('/', (req, res) => res.send('User Route'));

// @route:   POST api/users
// @desc:    Create user route
// @access:  Public
router.post(
    '/',
    [
        check('name', 'Name is required').not().isEmpty(),
        check('email', 'Please include a valid email').isEmail(),
        check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 })
    ],
    async (req, res) => {
        //check our validation
        const errors = validationResult(req);

        //check if any errors
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        //distructure components from the request
        const { name, email, password } = req.body;
        try {
            //check if user already exist
            let user = await User.findOne({ email });

            //if user exist - respond with error
            if (user) return res.status(400).json({ errors: [{ message: "User Already Exists" }] });

            //create a user
            user = new User({ name: name, email: email, password: password })

            //Encrypt users password
            const salt = await bcrypt.genSalt(10);

            user.password = await bcrypt.hash(password, salt);

            await user.save();

            //create payload to keep user signed in

            const payload = {
                user : { id : user._id}
            }

            //create and sign jwt
            jwt.sign(
                payload,
                process.env.jwtToken, 
                {expiresIn: 3600},
                (err,token)=>{
                    if(err) throw err;
                    return res.status(201).json({token})
                }
            );

        } catch (err) {
            return res.status(500).json({ errors: [{ ...err }] });
        }
    }
);

module.exports = router;
