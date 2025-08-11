import express from 'express';
import 'dotenv/config';
import './src/db/connectDB.js';
import router from './src/routers/authRouter.js';
import passport from "passport";
import './src/config/passport.js';
import cookieParser from 'cookie-parser';
import cors from 'cors'; 

const app = express();
const PORT = process.env.PORT || 5000;

const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";

app.use(cors({
  origin: CLIENT_URL, // Yalnız bu URL-dən gələn sorğulara icazə ver
  credentials: true, // Sorğularla birlikdə çerezlərin (cookies) göndərilməsinə icazə ver
}));

app.use(express.json());
app.use(passport.initialize());
app.use(cookieParser());

app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.use('/api/auth', router);

app.listen(PORT, () => {
    console.log(`Server is running http://localhost:${PORT}`);
});
