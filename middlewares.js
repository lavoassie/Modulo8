const jwt = require('jsonwebtoken')

const llave_secreta = 'topsecret'


function auth_required (req, res, next) {
  // quiero que esta ruta sólo sea para usuarios logueados
  // Si puedo abrir el token, entonces asumimos que el usuario SI está logueado
  // 1. Verificamos que tenga un token válido
  const {authorization} = req.headers
  
  let decoded;
  try {
    decoded = jwt.verify(authorization, llave_secreta)
  }
  catch(error) {
    console.log('error en la decodificacion', error)
    return res.status(400).json(error)
  }
  // 2. Verificamos que el token aún no ah expirado
  const now = (new Date() / 1000)
  if (now > decoded.exp) {
    console.log({now}, {exp: decoded.exp})
    return res.status(401).json({
      err: 'Tu token expiró'
    })
  }
  // 3. Guardamos el usuario en el objeto request
  req.data = decoded.data
  // 4. Si está todo ok, procedemos con el camino tradicional
  next()
}

module.exports = {auth_required, llave_secreta}