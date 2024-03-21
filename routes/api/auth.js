const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const User = require('../../models/User');
const auth = require('../../middleware/auth');

const router = express.Router();

// @route:   GET api/auth
// @desc:    Test route
// @access:  Public
router.get('/', (req, res) => res.send('Auth Route'));

// @route:   GET api/auth
// @desc:    Get user data
// @access:  Private
router.get('/private', auth, async (req, res) => {
    //try and get User info from DB
    try {
        //take all information about user except password
        const user = await User.findById(req.user.id).select('-password');
        return res.status(200).json({ data: user })

    } catch (err) {
        console.error(err)
        return res.status(500).json({ errors: [{ ...err }] });
    }
})

// @route:   POST api/auth
// @desc:    Log In and authenticate user
// @access:  Public
router.post(
    '/login',
    [
        check('email', 'Please include a valid email').notEmpty(),
        check('password', 'Password required').notEmpty()
    ],
    async (req, res) => {
        //check our validation
        const errors = validationResult(req);

        //check if any errors
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        //distructure components from the request
        const { email, password } = req.body;

        try {
            //check if user already exist
            let user = await User.findOne({ email });
            console.log(user)

            //if user exist - respond with error
            if (!user) return res.status(400).json({ errors: [{ message: "Invalid credentials" }] });

            const isMarch = await bcrypt.compare(password, user.password)

            //if password don't match
            if (!isMarch) return res.status(400).json({ errors: [{ message: "Invalid credentials" }] });

            //create payload to keep user signed in

            const payload = {
                user: { id: user._id, }
            }

            //create and sign jwt
            jwt.sign(
                payload,
                process.env.jwtToken,
                { expiresIn: 3600 },
                (err, token) => {
                    if (err) throw err;
                    return res.status(201).json({ token })
                }
            );


        } catch (err) {
            console.log(err)
            return res.status(500).json({ errors: [{message: err.message} ] });
        }
    }
)


module.exports = router;
