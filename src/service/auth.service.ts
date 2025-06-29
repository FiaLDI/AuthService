import { pool } from "../config/db";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import process from "process";

dotenv.config();

export class AuthService {
    async register(user) {
        if (user.password) {
            const hashedPassword = await bcrypt.hash(user.password, 10);
            const result = await pool.query(
                `
                    INSERT INTO users 
                    (email, userpassword) 
                    VALUES ($1, $2) 
                    RETURNING user_id
                `,
                [user.email, hashedPassword],
            );
            await pool.query(
                `
                    INSERT INTO personalData 
                    (
                        user_id, 
                        email,
                        username, 
                        phoneNumber, 
                        firstName, 
                        secondName, 
                        age, 
                        gender, 
                        aboutuser
                    ) 
                    VALUES (
                        $1, 
                        $2, 
                        $3, 
                        $4, 
                        $5, 
                        $6, 
                        $7, 
                        $8, 
                        $9
                    )
                `,
                [
                    result.rows[0].user_id,
                    user.email,
                    user.username,
                    user.phoneNumber,
                    user.name,
                    user.secondName,
                    user.age,
                    user.gender,
                    user.aboutUser,
                ],
            );

            return result.rows[0].user_id;
        }
        return "no";
    }

    async login(email, password) {
        const result = await pool.query(
            "SELECT * FROM users WHERE email = $1",
            [email],
        );
        const user = result.rows[0];
        if (user && (await bcrypt.compare(password, user.userpassword))) {
            const checker = await this.checkAuth(email);
            if (!checker) {
                const token = jwt.sign(
                    { id: user.user_id },
                    process.env.JWT_SECRET,
                    { expiresIn: "1h" },
                );
                await pool.query(
                    `
                    INSERT INTO usertoken
                    (user_id, token, startIn, expiresIn) 
                    VALUES($1, $2, $3, $4)
                    `,
                    [
                        user.user_id,
                        token,
                        new Date().toLocaleString(),
                        new Date().toLocaleString() + 1,
                    ],
                );
                const personal = await this.personal(token);
                return { token: token, user: personal };
            }
        }
        return { token: "", user: [] };
    }

    async logout(token) {
        await pool.query("DELETE FROM usertoken WHERE token = $1", [token]);
    }

    async personal(token) {
        const personal = await pool.query(
            `
            SELECT 
                u.email,
                p.username,
                p.phonenumber as "phoneNumber",
                p.firstname as "name",
                p.secondname as "secondName",
                p.age,
                p.gender

            FROM users u
            JOIN personaldata p on u.user_id = p.user_id
            JOIN usertoken ut ON u.user_id = ut.user_id
            WHERE ut.token = $1
        `,
            [token],
        );
        return personal.rows[0];
    }

    async checkEmail(email) {
        const personal = await pool.query(
            `
            SELECT 
                users.email
            FROM users
            WHERE users.email = $1
        `,
            [email],
        );
        if (personal.rows.length > 0) {
            return true;
        }
        return false;
    }

    async checkAuth(email) {
        const checkerActiveToken = await pool.query(
            `
            SELECT 
                ut.token
            FROM users u
            JOIN usertoken ut ON u.user_id = ut.user_id
            WHERE u.email = $1
        `,
            [email],
        );
        if (checkerActiveToken.rows.length > 0) {
            return true;
        }
        return false;
    }
}
