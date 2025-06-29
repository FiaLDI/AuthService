import dotenv from "dotenv";
import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import fs from "fs";
import { authRoutes } from "./routes/authRoutes";
import { connectRedis } from "./config/redis.config";
import https from "https";

dotenv.config();

const options = {
    key: fs.readFileSync("./src/selfsigned_key.pem"),
    cert: fs.readFileSync("./src/selfsigned.pem"),
};
connectRedis();

const app = express();
app.use(
    cors({
        origin: "https://26.234.138.233:5173",
        credentials: true,
    }),
);
const server = https.createServer(options, app);

app.use(cookieParser());
app.use(express.json());
app.use("/api", authRoutes);

const PORT = process.env.AUTHPORT || 3002;
server.listen(PORT, () => {
    // Запускаем сервер
    console.log(`Server is running on port ${PORT}`);
});
