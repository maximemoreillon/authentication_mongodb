const express = require('express')
const pjson = require('../package.json')
const dotenv = require('dotenv')
const authentication_controller = require('../controllers/authentication.js')
const mongodb = require('../mongodb.js')

// Parse .env file
dotenv.config()

let router = express.Router()


// middleware that is specific to this router
router.use( (req, res, next) => {
  next()
})

router.get('/', (req, res) => {
  res.send('Authentication API (MongoDB version), Maxime MOREILLON')
})

router.get('/info', (req, res) => {
  res.send({
    name: pjson.name,
    author: pjson.author,
    version: pjson.version,
    mongodb_url: mongodb.url,
    mongodb_db: mongodb.db,
    mongodb_collection: mongodb.collection,
  })
})

router.post('/login', authentication_controller.login)

// Token management
router.post('/verify_token', authentication_controller.decode_token)
router.post('/verify_jwt', authentication_controller.decode_token)







module.exports = router
