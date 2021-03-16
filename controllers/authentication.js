const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const dotenv = require('dotenv')
const mongodb = require('../mongodb.js')

dotenv.config()


const find_user_in_db = (identifier) => {

  return new Promise ( (resolve, reject) => {

    mongodb.MongoClient.connect( mongodb.url, mongodb.options)
    .then(db => {
      // prepare the query
      const query = { $or: [
        { username: identifier },
        { email_address: identifier },
        { email: identifier },
        { _id: identifier },
      ]}

      return db.db(mongodb.db)
      .collection(mongodb.collection)
      .findOne(query)
    })
    .then( user => {
      // Handle user not being found
      // NOT IDEAL
      if(!user) return reject({code: 400, message: `User ${identifier} not found in the database`})

      // Resolve with user
      resolve(user)

      console.log(`[MongoDB] User ${user._id} found in the database`)
    })
    .catch(error => {
      reject({code: 500, message: error})
    })

  })
}

const check_password = (password_plain, user) => {
  return new Promise ( (resolve, reject) => {

    const password_hashed = user.password_hashed

    bcrypt.compare(password_plain, password_hashed, (error, password_correct) => {

      if(error) return reject({code: 500, message: error})

      if(!password_correct) return reject({code: 403, message: `Incorrect password`})

      resolve(user)

      console.log(`[Auth] Password correct for user ${user._id}`)

    })

  })
}

const generate_token = (user) => {
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

      console.log(`[Auth] Token generated for user ${user._id}`)

    })
  })
}

const verify_token = (token) => {
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


const retrieve_token_from_body_or_query = (req) => {
  return new Promise ( (resolve, reject) => {

    const token = req.body.token
      || req.body.jwt
      || req.query.jwt
      || req.query.token

    if(!token) return reject({code: 400, message: `Missing token`})

    resolve(token)

  })
}

const retrieve_token_from_headers = (req) => {
  return new Promise ( (resolve, reject) => {

    // Check if authorization header set
    if(!req.headers.authorization) return reject({code: 400, message: `Authorization header not set`})
    // parse the headers to get the token
    const token = req.headers.authorization.split(" ")[1];
    if(!token) return reject({code: 400, message: `Token not found in authorization header`})

    resolve(token)

  })
}

const error_handling = (res, error) => {
  console.log(`[Auth] ${error.message || error}`)
  res.status(error.code || 500).send(error.message || error)
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
  .then( user => check_password(password, user) )
  .then( generate_token )
  .then( jwt => { res.send({jwt}) })
  .catch( error => { error_handling(res, error) })

}

exports.decode_token = (req, res) => {

  retrieve_token_from_body_or_query(req)
  .then( token => {return verify_token(token)})
  .then(decoded_token => { res.send(decoded_token) })
  .catch( error => { error_handling(res, error) })

}

exports.find_user_using_token = (req, res) => {

  retrieve_token_from_body_or_query(req)
  .then( token => {return verify_token(token)})
  .then( decoded_token => {

    const user_id = decoded_token.user_id
    if(!user_id) throw {code: 400, message: `No user ID in token`}

    try {
      const identifier = mongodb.ObjectID(user_id)
      return find_user_in_db(identifier)
    } catch (e) {
      throw `Invalid user ID`
    }

  })
  .then( user => {
    console.log(`[Auth] user ${user._id} retrieved using token`)
    res.send(user)
  })
  .catch(error => { error_handling(res, error) })

}

exports.whoami = (req, res) => {

  retrieve_token_from_headers(req)
  .then( token => {return verify_token(token)})
  .then( decoded_token => {

    const user_id = decoded_token.user_id
    if(!user_id) throw {code: 400, message: `No user ID in token`}

    try {
      const identifier = mongodb.ObjectID(user_id)
      return find_user_in_db(identifier)
    } catch (e) {
      throw `Invalid user ID`
    }

  })
  .then( user => {
    console.log(`[Auth] user ${user._id} retrieved using token`)
    res.send(user)
  })
  .catch(error => { error_handling(res, error) })

}
