const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt' );
const { sendEmail } = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');
const jwt = require('jsonwebtoken')

const getAll = catchError(async(req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    //destructuramos password y el resto -> del message -> del html -> send email
    const {password, email, firstName, frontBaseUrl } = req.body
    //encriptamos el password
    const hashedPassword = await bcrypt.hash(password, 10)
    //guardamos el body en una constante para usar despues
    const newBody = {...req.body, password: hashedPassword }
    const result = await User.create(newBody);

    //GENERAMOS EL CODIGO
    const code = require('crypto').randomBytes(64).toString('hex')
       
        //GUARDAMOS EL CODIGO
        await EmailCode.create(
            {
                code: code,
                userId: result.id
            }
        )
        //ENVIO DE EMAIL
        sendEmail({
            to: email,
            subject: 'verificacion de cuenta',
            html: `
            <div style="max-width: 500px; margin: 50px auto; background-color: #f8fafc; padding: 30px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); font-family: 'Arial', sans-serif; color: #333333;">
          
          <h1 style="color: #007BFF; font-size: 28px; text-align: center; margin-bottom: 20px;">¡Hola ${firstName.toUpperCase()} 👋!</h1>    
          
          <p style="font-size: 18px; line-height: 1.6; margin-bottom: 25px; text-align: center;">Gracias por registrarte en nuestra aplicación. Para verificar su cuenta, haga clic en el siguiente enlace:</p>
          
          <div style="text-align: center;">
              <a href="${frontBaseUrl}/verify_email/${code}" style="display: inline-block; background-color: #007BFF; color: #ffffff; text-align: center; padding: 14px 28px; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 18px;">¡Verificar cuenta!</a>
          </div>
        </div>
            `
        })
        return res.status(201).json(result);
});

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.destroy({ where: {id} });
    if(!result) return res.sendStatus(404);
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;

    const fieldsToNotShow = ['email', 'password', 'isVerifed']
    fieldsToNotShow.forEach(field => {
        delete req.body[field]
    })
    
    const result = await User.update(
        req.body,
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyUser = catchError(async (req, res) => {
    const {code } = req.params

    const userCode = await EmailCode.findOne({where: {code}})
    if(!userCode) return res.status(401).json({error: 'user not found'})

    const user = await User.findByPk(userCode.userId)

    await user.update(
        {isVerifed: true}
    )

    await userCode.destroy()

    return res.json(user)

})

const login = catchError(async(req, res) => {
    const {email, password } = req.body
    const user = await User.findOne({ where: {email}} )
    if (!user) res.sendStatus(401)

    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) res.sendStatus(401)

    const token = jwt.sign( {user}, 
        process.env.TOKEN_SECRET,
         { expiresIn: "1d"})

    return res.json({user, token})
})

const logged = catchError(async(req, res) => {
  const user = req.user
  return res.json(user) 
})

// const reset_passwordBody = catchError(async (req, res) => {

// })


module.exports = {
    getAll,
    create,
    getOne,
    update,
    remove,
    verifyUser,
    login,
    logged
    // reset_passwordBody
}