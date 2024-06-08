const router = require('express').Router()
const { where } = require('sequelize')
const db = require("../models")
const bcrypt = require('bcrypt')
const jwt = require('json-web-token')

const { User } = db

router.post('/', async (req, res) => {
    let user = await User.findOne({
        where: { email: req.body.email }
    })

    if (!user || !await bcrypt.compare(req.body.password, user.passwordDigest )) {
        req.status(404).json({
            message: `Could not find a user with the provided username and password`
        })
    }   else {
        const result = await jwt.encode(process.env.JWT_SECRET, { id: user.userId })
            res.json({ user: user, token: result.value })
    }
})

router.get('/profile', async (req, res) => {
    try {
        //Split the authorization indo header [ "Bearer", "TOKEN"]:
        const [authenticationMethod, token] = req.headers.authorization.split('')

        //Only handle "Bearer" authorization for now
        //(we could add other authorization strategies later):
        if (authenticationMethod == 'Bearer') {
            // decode the JWT
            const result = await jwt.decode(process.env.JWT_SECRET, token)

            //get logged in user's id from payload
            const { id } = result.value
        

        let user = await User.findOne({
            where: {
                userId: id
            }
        })
        res.json(user)
        }
    } catch (error) {
        res.json(null)
    }
})

module.exports = router