const jwt = require('jsonwebtoken')
const config = require('config')

module.exports = (req, res, next) => {
    if(req.method === 'OPTIONS') { //проверка на доступность сервера
        return next()
    }

    try {
        const token = req.headers.authorization.split(' ')[1] //заголовок jwt токена
        if(!token) {
            return res.status(401).json({message: 'Нет авторизации'})
        }

        const decode = jwt.verify(token, config.get('jwtSecret')) //разкодирует зашифрованный токен
        req.user = decode
        next()
    } catch (e) {
        return res.status(401).json({message: 'Нет авторизации'})
    }
}