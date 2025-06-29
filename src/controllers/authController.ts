import jwt from "jsonwebtoken";
import { redisClient } from "../config/redis.config";
import { pool } from "../config/db";
import bcrypt from "bcrypt";
import { Request, Response } from "express";

export const sendCodeCheck = async (req: Request, res: Response) => {
    try {
        const { email } = req.body;

        // Валидация email
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: "Valid email is required" });
        }

        // Генерация 10-значного цифрового кода
        const code = Math.floor(
            1000000000 + Math.random() * 9000000000,
        ).toString();
        // Сохранение в Redis на 5 минут (300 секунд)
        await redisClient.setEx(email, 300, code);
        console.log(`Verification code ${code} generated for ${email}`);

        // В реальном приложении здесь должна быть отправка кода по email
        // Например: await sendEmail(email, code);
        res.json({
            message: "Verification code generated and stored",
            email,
            code, // В продакшне не возвращайте код в ответе!
        });
    } catch (err) {
        console.error("Error in sendCodeCheck:", err);
        res.status(500).json({ error: "Internal server error" });
    }
};

export const verifyCode = async (req: Request, res: Response) => {
    try {
        const { email, code } = req.body;

        // Валидация входных данных
        if (!email || !code) {
            return res
                .status(400)
                .json({ error: "Email and code are required" });
        }

        // Получаем код из Redis
        const storedCode = await redisClient.get(email);

        if (!storedCode) {
            return res.status(404).json({ error: "Code not found or expired" });
        }

        // Сравниваем коды (без учета регистра, если нужно)
        if (storedCode !== code) {
            return res.status(401).json({ error: "Invalid verification code" });
        }

        // Удаляем код из Redis после успешной проверки
        await redisClient.del(email);

        res.json({
            message: "ok",
            verified: true,
        });
    } catch (err) {
        console.error("Error in verifyCode:", err);
        res.status(500).json({ error: "Internal server error" });
    }
};

export const register = async (req: Request, res: Response) => {
    const client = await pool.connect();
    try {
        const { email, password, display_name, username, birth_date } =
            req.body;

        // Валидация обязательных полей
        if (!email || !password || !display_name || !username || !birth_date) {
            return res.status(400).json({ error: "All fields are required" });
        }

        // Проверка формата email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: "Invalid email format" });
        }

        // Проверка сложности пароля
        if (password.length < 8) {
            return res
                .status(400)
                .json({ error: "Password must be at least 8 characters long" });
        }

        // Проверка уникальности email и username
        const userCheck = await client.query(
            `SELECT 1 FROM users WHERE email = $1 OR username = $2`,
            [email, username],
        );

        if (userCheck.rows.length > 0) {
            return res
                .status(409)
                .json({ error: "Email or username already exists" });
        }

        // Хеширование пароля
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Преобразование даты рождения
        const birthDate = new Date(birth_date);

        // Создание пользователя в транзакции
        await client.query("BEGIN");
        const result = await client.query(
            `INSERT INTO users 
       (email, password_hash, username) 
       VALUES ($1, $2, $3) 
       RETURNING id`,
            [email, hashedPassword, username],
        );

        // Создание профиля пользователя
        await client.query(
            `INSERT INTO user_profile 
        (user_id, birth_date, avatar_url) VALUES ($1, $2, $3)`,
            [result.rows[0].id, birthDate, "/img/icon.png"],
        );

        // Создание настроек пользователя
        await client.query(
            `INSERT INTO user_preferences 
        (user_id, created_at, confirmed_at) VALUES ($1, NOW(), NOW())`,
            [result.rows[0].id],
        );

        await client.query("COMMIT");

        // Удаляем verification code из Redis если он был
        await redisClient.del(email);

        // Генерация JWT токена (опционально)
        // const token = generateToken(result.rows[0].id);

        res.status(201).json({
            message: "User registered successfully",
            user: {
                id: result.rows[0].id,
            },
            // token: token // если используется JWT
        });
    } catch (err: any) {
        await client.query("ROLLBACK");
        console.error("Registration error:", err);
        if (err.code === "23505") {
            // Ошибка уникальности в PostgreSQL
            return res.status(409).json({ error: "User already exists" });
        }
        res.status(500).json({ error: "Internal server error" });
    } finally {
        client.release();
    }
};

export const login = async (req: Request, res: Response) => {
    const client = await pool.connect();

    try {
        const { email, password } = req.body;
        console.log(password);
        const user = await client.query(
            `SELECT * FROM users WHERE email = $1`,
            [email],
        );

        if (user.rows.length != 1) {
            return res.status(409).json({ error: "Not Found" });
        }
        const isPasswordValid = await bcrypt.compare(
            password,
            user.rows[0].password_hash,
        );

        if (!isPasswordValid) {
            return res.status(401).json({ error: "Invalid credentials" });
        }
        const accessToken = jwt.sign(
            { id: user.rows[0].id },
            process.env.ACCESS_TOKEN_SECRET!,
            { expiresIn: "15m" },
        );
        const refreshToken = jwt.sign(
            { id: user.rows[0].id },
            process.env.REFRESH_TOKEN_SECRET!,
            { expiresIn: "7d" },
        );

        res.clearCookie("refresh_token", {
            httpOnly: true,
            secure: false,
            sameSite: "lax",
            path: "/",
        });

        res.cookie("refresh_token", refreshToken, {
            httpOnly: true,
            secure: false,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        const userInformation = await client.query(
            `
        select u.id, u.username, up.avatar_url from users u
        JOIN user_profile up ON up.user_id = u.id 
        WHERE u.id = $1
      `,
            [user.rows[0].id],
        );

        res.json({
            access_token: accessToken,
            username: user.rows[0].username,
            info: userInformation.rows[0],
        });
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: "Internal server error" });
    } finally {
        client.release();
    }
};

export const refresh = async (req: Request, res: Response) => {
    const client = await pool.connect();
    const refreshToken = req.cookies.refresh_token;

    if (!refreshToken) {
        return res.status(401).json({ error: "Refresh token missing" });
    }

    try {
        const decoded = jwt.verify(
            refreshToken,
            process.env.REFRESH_TOKEN_SECRET!,
        ) as jwt.JwtPayload;
        const user = await client.query(`SELECT * FROM users WHERE id = $1`, [
            decoded.id,
        ]);

        if (user.rows.length != 1) {
            return res.status(401).json({ error: "User not found" });
        }

        // Генерация нового access-токена
        const accessToken = jwt.sign(
            { id: user.rows[0].id },
            process.env.ACCESS_TOKEN_SECRET!,
            {
                expiresIn: "15m",
            },
        );

        const userInformation = await client.query(
            `
        select u.id, u.username, up.avatar_url from users u
        JOIN user_profile up ON up.user_id = u.id 
        WHERE u.id = $1
      `,
            [decoded.id],
        );

        res.json({
            access_token: accessToken,
            username: user.rows[0].username,
            info: userInformation.rows[0],
        });
    } catch (error) {
        console.log(error);
        res.status(401).json({ error: "Invalid refresh token" });
    } finally {
        client.release();
    }
};

export const protectedRoute = (req: Request, res: Response) => {
    res.json({ message: "This is a protected route", user: (req as any).user });
};

export const logout = (req: Request, res: Response) => {
    res.clearCookie("refresh_token", {
        httpOnly: true,
        secure: false, // Для локальной разработки
        sameSite: "lax", // Для локальной разработки
        path: "/", // Указываем путь
    });
    res.json({ message: "User logout" });
};
