import express from "express";
import cors from "cors";
import "dotenv/config";
import cookieParser from "cookie-parser";
import connectDB from './config/mongodb.js';
import authRouter from "./routes/authRoutes.js";
import userRouter from "./routes/userRoute.js";

const app = express();
const port = process.env.PORT || 4000;
connectDB()

app.use(express.json());
app.use(cookieParser());

// Your frontend origin which is link wiht these backgrounde
const allowedOrigins = ['http://localhost:5173','http://localhost:5174']
app.use(cors({
  origin: allowedOrigins, 
  credentials: true
}));

// API ENDPOINT
app.get("/", (req, res) => {
  res.send("server is live is good");
});

app.use('/api/auth',authRouter)
app.use('/api/user',userRouter)

app.listen(port, (req, res) => {
  console.log("app is litening at port : ", port);
});
