import jwt from "jsonwebtoken";
import { NextFunction, Request, Response } from "express";

export const authenticate = (
    req: Request,
    res: Response,
    next: NextFunction,
) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ error: "Access token missing" });
    }

    try {
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!);
        (req as any).user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: "Invalid access token" });
    }
};
