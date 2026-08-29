"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const client_1 = require("@prisma/client");
const zod_1 = require("zod");
const shared_1 = require("@sentinel/shared");
const auth_1 = require("../middleware/auth");
const router = (0, express_1.Router)();
const prisma = new client_1.PrismaClient();
router.post('/login', async (req, res) => {
    try {
        const { email, password } = shared_1.loginSchema.parse(req.body);
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user)
            return res.status(401).json({ error: 'Invalid credentials' });
        const isValid = await bcrypt_1.default.compare(password, user.passwordHash);
        if (!isValid)
            return res.status(401).json({ error: 'Invalid credentials' });
        const userContext = { id: user.id, email: user.email, role: user.role };
        const token = jsonwebtoken_1.default.sign(userContext, auth_1.SECRET_KEY);
        const response = { token, user: userContext };
        res.json(response);
    }
    catch (err) {
        if (err instanceof zod_1.ZodError) {
            return res.status(400).json({ error: 'Email and password required' });
        }
        return res.status(500).json({ error: 'Database error' });
    }
});
router.post('/seed', async (req, res) => {
    try {
        const existing = await prisma.user.findUnique({ where: { email: 'admin@sentinel.local' } });
        if (existing)
            return res.json({ message: 'Already seeded' });
        const hash = await bcrypt_1.default.hash('admin123', 10);
        await prisma.user.create({
            data: {
                id: 'admin-uuid',
                email: 'admin@sentinel.local',
                passwordHash: hash,
                role: 'admin'
            }
        });
        res.json({ message: 'Seeded admin@sentinel.local / admin123' });
    }
    catch (err) {
        res.status(500).json({ error: 'Failed to seed', details: String(err) });
    }
});
exports.default = router;
