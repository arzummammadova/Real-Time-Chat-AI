import Joi from "joi"

export const registerValidation=Joi.object({
    username:Joi.string().min(3).max(20).required(),
    email:Joi.string().min(3).max(50).required(),
    password:Joi.string().pattern(/^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-={}[\]|:;"'<>,.?/~`]).{8,20}$/),


})

export const loginValidation = Joi.object({
  user: Joi.string().min(3).max(50).required(),  // həm username, həm email üçün istifadə olunacaq
  password: Joi.string()
    .pattern(/^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-={}[\]|:;"'<>,.?/~`]).{8,20}$/)
    .required(),
});