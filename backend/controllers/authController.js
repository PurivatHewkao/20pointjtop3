// controllers/authController.js
const fs = require('fs');
const path = require('path');

// อ้างอิงกลับไปที่ root folder
const USERS_FILE = path.join(__dirname, '../users.json');

const getUsers = () => {
    if (!fs.existsSync(USERS_FILE)) {
        fs.writeFileSync(USERS_FILE, '[]');
        return [];
    }
    const data = fs.readFileSync(USERS_FILE, 'utf8');
    return data ? JSON.parse(data) : [];
};

const saveUsers = (users) => {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
};

exports.register = (req, res) => {
    const { username, password } = req.body;
    let users = getUsers();

    if (users.find(u => u.username === username)) {
        return res.status(400).json({ success: false, message: 'Username นี้มีคนใช้แล้ว' });
    }

    const role = users.length === 0 ? 'admin' : 'user';
    users.push({ username, password, role }); 
    saveUsers(users);

    res.json({ success: true, message: `สมัครสมาชิกสำเร็จ! คุณได้รับสิทธิ์เป็น ${role.toUpperCase()}` });
};

exports.login = (req, res) => {
    const { username, password, loginType } = req.body;
    const users = getUsers();
    const user = users.find(u => u.username === username && u.password === password);

    if (!user) {
        return res.status(401).json({ success: false, message: 'Username หรือ Password ไม่ถูกต้องค่ะ' });
    }

    if (user.role !== loginType) {
        return res.status(403).json({ 
            success: false, 
            message: `บัญชีนี้เป็น ${user.role} แต่คุณพยายามเข้าสู่ระบบในหน้า ${loginType} ค่ะ` 
        });
    }

    res.json({ success: true, message: `ยินดีต้อนรับคุณ ${username} (${user.role})` });
};

exports.resetPassword = (req, res) => {
    const { username, newPassword } = req.body;
    let users = getUsers();
    const userIndex = users.findIndex(u => u.username === username);

    if (userIndex !== -1) {
        users[userIndex].password = newPassword;
        saveUsers(users);
        res.json({ success: true, message: 'อัปเดตรหัสผ่านใหม่เรียบร้อยแล้วค่ะ' });
    } else {
        res.status(404).json({ success: false, message: 'ไม่พบ Username นี้ในระบบค่ะ' });
    }
};