import express from 'express';
import 'dotenv/config'
import './src/db/connectDB.js'
const app=express();
const PORT=process.env.PORT || 5000;
app.use(express.json())
app.get('/',(req,res)=>{
    res.send('Hello World! ')
})
app.listen(PORT,()=>{
    console.log(`Server is running http://localhost:${PORT}`);

})