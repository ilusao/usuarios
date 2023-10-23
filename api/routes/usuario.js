/* API REST dos prestadores */
import express from 'express'
import { connectToDatabase } from '../utils/mongodb.js'
import { check, validationResult } from 'express-validator'

const router = express.Router()
const {db, ObjectId} = await connectToDatabase()
const nomeCollection = 'usuarios'
//JWT

import auth from '../middleware/auth.js'
import bcrypt from 'bcryptjs'
import  Jwt  from 'jsonwebtoken'
import { ValidationHalt } from 'express-validator/src/base.js'

/*****************
 * validações
 ******************/
const validaUsuario =  [
     check('nome')
    .not().isEmpty().trim().withMessage('seu nome meu')
    .isAlpha('pt-BR', {ignore : ' '}).withMessage('apenas o nome')
    .isLength({max :100}).withMessage('tenho certeza que seu nome não passa de 100 caracteres')
    .isLength({min: 3}).withMessage('certeza que seu nome é esse?'),
    check('email')
    .not().isEmpty().trim().withMessage('seu email meu')
    .isLowercase().withMessage('sem maiusculo... eu sei é chato isso')
    .isEmail().withMessage('cara... não tem o @')
    .custom((value, {req}) => {
        return db.collection(nomeCollection).find({email: {$eq:
        value}}).toArray()
        .then((email)=> {
            // verifica se não tem o IdleDeadline, para garantir que é inclusão
            if (email.length && !req.params.id){
                return Promise.reject(`se acredita que o email ${value} já existe `)
            }
        })
    }),
    check ('senha')
    .not().isEmpty().trim().withMessage('cade a senha???')
    .isLength({min:6}).withMessage('até parece que você vai lenbra de tudo isso, minimo 6 caracter')
    .isStrongPassword({minLength: 6, minLowercase: 1, minUppercase: 1, minSymbols: 1})
                      .withMessage('que senha merda! minimo 1 caractere maiusculo, 1 caractere minusculo, 1 número e 1 caractere especial'),

    check ('ativo')
    .default(true)
    .isBoolean().withMessage('os valor deve ser um booleano. true ou false'),

    check ('tipo')
    .default('cliente')
    .isIn(['admin', 'cliente']).withMessage('adm ou cliente'),

    check ('avatar')
    .optional({ nullable: true}) // permitir usuarios sem avatar
    .isURL().withMessage('URL precisa ser valida')

    



]
//Post de usuário
router.post('/', validaUsuario, async(req, res)=>{
     const schemaErrors = validationResult(req)
      if (!schemaErrors.isEmpty()){
        return res.status(403).json(({
            errors: schemaErrors.array()
        }))
      } else{
        // definindo o avatar default
        req.body.avatar =  `https://ui-avatars.com/api/?name=${req.body.nome.replace(/ /g, '+')}&background=F00&color=fff`

        // criptografia da senha
        // genSalt => impede que 2 senhas igaus tenham resuldatos resultados iguais
        
        const salt = await bcrypt.genSalt(10)
        req.body.senha = await bcrypt.hash(req.body.senha, salt)
        // iremos salvar o registro
        await db.collection(nomeCollection)
        .insertOne(req.body)
        .then(result => res.status(201).send(result))
        .catch(err => res.status(400).json(err))

      }
})

//login
/******fogo**************************************
 * POST/usuarios/login
 * efetua o login do usuario e retorna o token JWT
 *******agua*************************************/
const validalogin = [
   check('email')
   .not().isEmpty().trim().withMessage('cade o email meu ?')
   .isEmail().withMessage('coloca o email certo, so vidente não'),

   check('senha')
   .not().isEmpty().trim().withMessage('cade a senha meu ?')
   .isLength({min:6}).withMessage('calma la parceiro nem você vai lembra esse tradato, minimo 6 carac.')
   
]
router.post('/login',validalogin, async(req, res)=> {
    const schemaErrors = validationResult(req)
    if(!schemaErrors.isEmpty()){
        return res.status(403).json(({errors: schemaErrors.array()}))
    
}
//obtendo  os valores do login
const {email,senha} = req.body
try{
    //verificar se o email informado existe no mongodb
    let usuario = await db.collection(nomeCollection)
                          .find({email}).limit(1).toArray()
                          //se o rray estiver vazio,é que o email não existe
    if(!usuario.length)
    return res.status(404).json({
        errors: [{
            value:  `${email}`,
            msg: 'se acredita que não existe esse email',
            param: 'email'}]
    })
    const isMatch = await bcrypt.compare(senha, usuario[0].senha)
    if(!isMatch)
    return res.status(404).json({
        errors:  [{
            value:  `senha`,
            msg: 'se acredita que não existe essa senha',
            param: 'senha'}]
    })
//iremos gerar o token JWT
Jwt.sign(
    {usuario: {id: usuario[0]._id}},
    process.env.SECRET_KEY,
    {expiresIn: process.env.EXPIRES_IN},
    (err,token) => {
        if(err) throw err 
        res.status(200).json({
            acess_token: token
        })
    }
)
}catch(e){
    console.error(e)
}

})

/**************************************************
 * get /usuarios
 * lista todos os ousuarios. necessita do token
 * 
 *************************************************/

router.get('/', auth,async(req, res)=>{
    try{
    db.collection(nomeCollection)
    .find({},{projection: {senha:false}})
    .sort({nome:1})
    .toArray((err,docs)=>{
        if(!err){res.status(200).json(docs)}
    })
 }catch(err){
    res.status(500).json({errors:
    [{msg: 'erro ao obter a listagem do usuario'}]})
 }

})

router.delete('/:id', auth,async(req,res)=> {
    await db.collection(nomeCollection)
    .deleteOne({'_id': {$eq: ObjectId(req.params.id)}})
    .then(result => res.status(202).send(result)) //aceito
    .catch(err => res.status(400).json(err)) // bad request
})

/***********************************************
 * PUT/quarios/id
 * altera os dados do usuario pelo id, necessita do token
 * 
 */
router.put('/:id', validaUsuario,async(req,res)=>{
    const schemaErrors = validationResult(req)
    if(!schemaErrors.isEmpty()){
        return res.status(403).json({
            errors: schemaErrors.array()
        })
    }else {
        await db.collection(nomeCollection)
        .updateOne({'_id': {$eq: ObjectId(req.params.id)}},
        {$set: req.body}
        )
        .then(result => res.status(202).send(result))
        .catch(err => res.status(400).json(err))
    }
})



export default router


