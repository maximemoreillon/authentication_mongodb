const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const dotenv = require('dotenv')
const mongodb = require('../mongodb.js')

dotenv.config()


let find_user_in_db = (identifier) => {

  return new Promise ( (resolve, reject) => {

    mongodb.MongoClient.connect( mongodb.url, mongodb.options, (error, db) => {

      // Handle DB connection errors
      if (error) return reject(error)

      // prepare the query
      const query = { $or: [
        { username: identifier },
        { email_address: identifier },
        { email: identifier },
      ]}

      db.db(mongodb.db)
      .collection(mongodb.collection)
      .findOne(query, (error, user) => {

        // Close the connection to the DB
        db.close()

        // Handle DB errors
        if (error) return reject({code: 500, message: error})

        // Handle user not being found
        if(!user) return reject({code: 400, message: `User ${identifier} not found in the database`})

        // Resolve with user
        resolve(user)

        console.log(`[MongoDB] User ${user.username} found in the database`)

      })
    })
  })
}

let check_password = (password_plain, user) => {
  return new Promise ( (resolve, reject) => {

    const password_hashed = user.password_hashed

    bcrypt.compare(password_plain, password_hashed, (error, password_correct) => {

      if(error) return reject({code: 500, message: error})

      if(!password_correct) return reject({code: 403, message: `Incorrect password`})

      resolve(user)

      console.log(`[Auth] Password correct for user ${user.username}`)

    })

  })
}

let generate_token = (user) => {
  return new Promise( (resolve, reject) => {

    const JWT_SECRET = process.env.JWT_SECRET

    // Check if the secret is set
    if(!JWT_SECRET) return reject({code: 500, message: `Token secret not set`})

    const token_content = { user_id: user._id }

    jwt.sign(token_content, JWT_SECRET, (error, token) => {

      // handle signing errors
      if(error) return reject({code: 500, message: error})

      // Resolve with token
      resolve(token)

      console.log(`[Auth] Token generated for user ${user.username}`)

    })
  })
}

let verify_token = (token) => {
  return new Promise ( (resolve, reject) => {

    const JWT_SECRET = process.env.JWT_SECRET

    // Check if the secret is set
    if(!JWT_SECRET) return reject({code: 500, message: `Token secret not set`})

    jwt.verify(token, JWT_SECRET, (error, decoded_token) => {

      if(error) return reject({code: 403, message: `Invalid JWT`})

      resolve(decoded_token)

      console.log(`[Auth] Token decoded successfully`)

    })
  })
}


exports.login = (req, res) => {

  // Input sanitation
  const user_identifier = req.body.username
    || req.body.email_address
    || req.body.email
    || req.body.identifier

  const password = req.body.password

  if(!user_identifier) return res.status(400).send(`Missing username or e-mail address`)
  if(!password) return res.status(400).send(`Missing password`)

  find_user_in_db(user_identifier)
  .then( user => { return check_password(password, user) })
  .then( user => { return generate_token(user) })
  .then( token => { res.send({jwt: token}) })
  .catch(error => {
    console.log(error.message || error)
    res.status(error.code || 500).send(error.message || error)
  })

}

exports.decode_token = (req, res) => {

  const token = req.body.token
    || req.body.jwt

  if(!token) return res.status(400).send(`Missing token`)

  verify_token(token)
  .then(decoded_token => { res.send(decoded_token) })
  .catch(error => {
    console.log(error.message || error)
    res.status(error.code || 500).send(error.message || error)
  })

}
