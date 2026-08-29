"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const shared_1 = require("@sentinel/shared");
const auth_1 = __importDefault(require("./routes/auth"));
const logs_1 = __importDefault(require("./routes/logs"));
const auth_2 = require("./middleware/auth");
const app = (0, express_1.default)();
const port = process.env.PORT || 3000;
app.use(express_1.default.json());
app.use('/api/auth', auth_1.default);
app.use('/api/logs', logs_1.default);
app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'server' });
});
// Protect /api/health
app.get('/api/health', auth_2.requireAuth, (req, res) => {
    const status = {
        status: 'ok',
        service: 'api',
        user: req.user
    };
    res.json(status);
});
app.listen(port, () => {
    console.log(`${shared_1.APP_NAME} backend listening on port ${port}`);
});
