// script.js
const API_URL = 'http://localhost:3000/api';

// ฟังก์ชันสลับหน้าต่าง (Tabs)
function switchTab(tabId) {
    // ปิดทุกฟอร์ม
    document.querySelectorAll('.form-section').forEach(el => el.classList.remove('active-form'));
    // เอาสีปุ่มออก
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));

    // เปิดฟอร์มเป้าหมาย
    document.getElementById(tabId).classList.add('active-form');

    // ไฮไลต์ปุ่ม (ตรวจสอบเพื่อไม่ให้พังในหน้าลืมรหัส)
    const btnMap = {
        'user-login': 0,
        'admin-login': 1,
        'register': 2
    };
    if (btnMap[tabId] !== undefined) {
        document.querySelectorAll('.tab-btn')[btnMap[tabId]].classList.add('active');
    }
}

// ฟังก์ชันแจ้งเตือนด้วย SweetAlert2
function showPopup(icon, title, text) {
    Swal.fire({
        icon: icon,
        title: title,
        text: text,
        confirmButtonColor: '#ff69b4',
        background: '#fff0f5'
    });
}

// ฟังก์ชันจัดการฟอร์มรวม (Login, Register, Reset)
async function handleAuth(event, action, loginType = null) {
    event.preventDefault();

    let endpoint = '';
    let payload = {};

    if (action === 'register') {
        endpoint = '/register';
        payload = {
            username: document.getElementById('reg-username').value,
            password: document.getElementById('reg-password').value
        };
    } else if (action === 'login') {
        endpoint = '/login';
        const prefix = loginType === 'admin' ? 'admin' : 'user';
        payload = {
            username: document.getElementById(`${prefix}-username`).value,
            password: document.getElementById(`${prefix}-password`).value,
            loginType: loginType
        };
    } else if (action === 'reset') {
        endpoint = '/reset-password';
        payload = {
            username: document.getElementById('reset-username').value,
            newPassword: document.getElementById('reset-newpassword').value
        };
    }

    try {
        const response = await fetch(`${API_URL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (data.success) {
            showPopup('success', 'สำเร็จ!', data.message);

            // ย้ายการ reset ฟอร์มออกไปจัดการแยกกัน
            if (action === 'register' || action === 'reset') {
                event.target.reset(); // รีเซ็ตเฉพาะตอนสมัครหรือเปลี่ยนรหัสผ่าน
                setTimeout(() => switchTab('user-login'), 1500);
            } else if (action === 'login') {
                // ✅ ใช้ค่า username จากตัวแปร payload ที่เราเก็บไว้ตั้งแต่แรก
                sessionStorage.setItem('username', payload.username);
                sessionStorage.setItem('role', loginType);

                event.target.reset(); // รีเซ็ตฟอร์มทีหลังสุดเมื่อเก็บข้อมูลเสร็จแล้ว

                setTimeout(() => {
                    window.location.href = 'index.html';
                }, 1500);
            }
        } else {
            showPopup('error', 'อ๊ะ!', data.message);
        }
    } catch (error) {
        showPopup('error', 'ข้อผิดพลาด', 'ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้ค่ะ');
        console.error(error);
    }
}