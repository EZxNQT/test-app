import time
import hmac
import hashlib
import secrets
from functools import wraps
from flask import Flask, request, jsonify, make_response, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

app = Flask(__name__)
JWT_SECRET = secrets.token_hex(32)
OTP_PEPPER = secrets.token_hex(16)

# Băm giả dùng để chống Timing Attack khi username không tồn tại
DUMMY_HASH = generate_password_hash("dummy_constant_time_defense_password")

# =====================================================================
# 1. CƠ SỞ DỮ LIỆU GIẢ LẬP TRONG BỘ NHỚ (IN-MEMORY STORE)
# =====================================================================
USERS_DB = {
    "vinh_ptit": {
        "password_hash": generate_password_hash("AnToan@2026"),
        "phone": "+84 987 *** 321",
        "failed_attempts": 0,
        "lockout_until": 0,
    }
}

# Lưu trữ Rate Limit theo IP: { ip: [timestamp1, timestamp2, ...] }
RATE_LIMIT_STORE = {}
RATE_LIMIT_MAX_REQ = 6
RATE_LIMIT_WINDOW = 30  # giây

# Lưu trữ CAPTCHA phía Server: { captcha_id: {"answer": str, "expires": float} }
CAPTCHA_STORE = {}

# Lưu trữ phiên chờ xác thực SMS MFA:
# { mfa_token: {"username": str, "otp_hash": str, "expires": float, "attempts": int} }
MFA_SESSIONS = {}

# Lưu trữ Refresh Token phục vụ Rotation & Reuse Detection:
# { token_id: {"username": str, "family_id": str, "used": bool, "revoked": bool, "expires": float} }
REFRESH_TOKENS = {}

# Hộp thư SMS giả lập để hiển thị lên giao diện Demo
VIRTUAL_SMS_INBOX = []


# =====================================================================
# 2. CÁC HÀM BẢO MẬT HỖ TRỢ (SECURITY HELPERS)
# =====================================================================
def hash_otp(otp_code: str) -> str:
    return hmac.new(OTP_PEPPER.encode(), otp_code.encode(), hashlib.sha256).hexdigest()


def create_captcha():
    a = secrets.randbelow(9) + 1
    b = secrets.randbelow(9) + 1
    captcha_id = secrets.token_urlsafe(12)
    CAPTCHA_STORE[captcha_id] = {
        "answer": str(a + b),
        "expires": time.time() + 180
    }
    return captcha_id, f"{a} + {b} = ?"


def verify_captcha(captcha_id: str, user_answer: str) -> bool:
    if not captcha_id or captcha_id not in CAPTCHA_STORE:
        return False
    record = CAPTCHA_STORE.pop(captcha_id)  # One-time use
    if time.time() > record["expires"]:
        return False
    return hmac.compare_digest(record["answer"], str(user_answer).strip())


def rate_limit_middleware():
    ip = request.remote_addr or "127.0.0.1"
    now = time.time()
    history = RATE_LIMIT_STORE.get(ip, [])
    # Lọc các request còn nằm trong cửa sổ thời gian
    history = [t for t in history if now - t < RATE_LIMIT_WINDOW]
    if len(history) >= RATE_LIMIT_MAX_REQ:
        retry_after = int(RATE_LIMIT_WINDOW - (now - history[0])) + 1
        return jsonify({
            "error": f"Quá nhiều yêu cầu (Rate Limit). Vui lòng thử lại sau {retry_after} giây.",
            "retry_after": retry_after
        }), 429
    history.append(now)
    RATE_LIMIT_STORE[ip] = history
    return None


def issue_token_pair(username: str, family_id: str = None):
    now = time.time()
    if not family_id:
        family_id = secrets.token_hex(8)

    # 1. Access Token ngắn hạn (60 giây để dễ kiểm thử)
    access_payload = {
        "sub": username,
        "iat": int(now),
        "exp": int(now + 60),
        "jti": secrets.token_hex(8),
        "type": "access"
    }
    access_token = jwt.encode(access_payload, JWT_SECRET, algorithm="HS256")

    # 2. Refresh Token (Quản lý trạng thái Rotation trên Server)
    refresh_id = secrets.token_urlsafe(32)
    REFRESH_TOKENS[refresh_id] = {
        "username": username,
        "family_id": family_id,
        "used": False,
        "revoked": False,
        "expires": now + 3600
    }
    return access_token, refresh_id, family_id


def revoke_token_family(family_id: str):
    """Thu hồi toàn bộ chuỗi Refresh Token cùng họ khi phát hiện bị đánh cắp (Reuse Detection)"""
    for tid, data in REFRESH_TOKENS.items():
        if data["family_id"] == family_id:
            data["revoked"] = True


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Thiếu Access Token"}), 401
        token = auth_header.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            request.user = payload["sub"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Access Token đã hết hạn (60s). Hãy gọi Refresh Token!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Access Token không hợp lệ"}), 401
        return f(*args, **kwargs)
    return decorated


# =====================================================================
# 3. CÁC API ĐĂNG NHẬP, MFA & QUẢN LÝ TOKEN
# =====================================================================
@app.route("/api/login", methods=["POST"])
def api_login():
    # Kiểm tra Rate Limit theo IP
    rl_resp = rate_limit_middleware()
    if rl_resp:
        return rl_resp

    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    captcha_id = data.get("captcha_id")
    captcha_answer = data.get("captcha_answer", "")

    now = time.time()
    user = USERS_DB.get(username)

    # Chống Timing Attack: Nếu user không tồn tại, vẫn chạy hàm băm giả
    if not user:
        check_password_hash(DUMMY_HASH, password)
        cid, c_question = create_captcha()
        return jsonify({
            "error": "Tên đăng nhập hoặc mật khẩu không chính xác.",
            "require_captcha": True,
            "captcha_id": cid,
            "captcha_question": c_question
        }), 401

    # Kiểm tra trạng thái khóa tạm thời (Soft Lockout)
    if now < user["lockout_until"]:
        wait_sec = int(user["lockout_until"] - now)
        return jsonify({
            "error": f"Tài khoản đang bị tạm khóa chống Brute-force. Thử lại sau {wait_sec} giây."
        }), 423

    # Nếu đã sai từ 2 lần trở lên, bắt buộc giải đúng CAPTCHA trước khi kiểm tra mật khẩu
    if user["failed_attempts"] >= 2:
        if not verify_captcha(captcha_id, captcha_answer):
            cid, c_question = create_captcha()
            return jsonify({
                "error": "Vui lòng giải đúng mã CAPTCHA bảo mật để tiếp tục.",
                "require_captcha": True,
                "captcha_id": cid,
                "captcha_question": c_question
            }), 400

    # Kiểm tra mật khẩu
    if not check_password_hash(user["password_hash"], password):
        user["failed_attempts"] += 1
        # Nếu sai 4 lần liên tiếp -> Khóa tạm thời 60 giây
        if user["failed_attempts"] >= 4:
            user["lockout_until"] = now + 60
            return jsonify({
                "error": "Nhập sai quá 4 lần! Tài khoản bị khóa tạm thời 60 giây."
            }), 423

        resp_payload = {"error": "Tên đăng nhập hoặc mật khẩu không chính xác."}
        if user["failed_attempts"] >= 2:
            cid, c_question = create_captcha()
            resp_payload["require_captcha"] = True
            resp_payload["captcha_id"] = cid
            resp_payload["captcha_question"] = c_question
        return jsonify(resp_payload), 401

    # Đăng nhập Bước 1 thành công -> Reset bộ đếm lỗi & Phát sinh SMS OTP
    user["failed_attempts"] = 0
    user["lockout_until"] = 0

    otp_code = f"{secrets.randbelow(900000) + 100000}"
    mfa_token = secrets.token_urlsafe(24)
    MFA_SESSIONS[mfa_token] = {
        "username": username,
        "otp_hash": hash_otp(otp_code),
        "expires": now + 180,
        "attempts": 0
    }

    # Gửi vào hộp thư SMS giả lập
    VIRTUAL_SMS_INBOX.insert(0, {
        "to": user["phone"],
        "time": time.strftime("%H:%M:%S"),
        "message": f"[AppSec Demo] Mã xác thực OTP của bạn là: {otp_code} (Hiệu lực 3 phút, không chia sẻ cho bất kỳ ai)."
    })

    return jsonify({
        "status": "MFA_REQUIRED",
        "message": f"Đã gửi mã SMS OTP tới số {user['phone']}",
        "mfa_token": mfa_token,
        "sms_preview": VIRTUAL_SMS_INBOX[0]
    })


@app.route("/api/verify-otp", methods=["POST"])
def api_verify_otp():
    rl_resp = rate_limit_middleware()
    if rl_resp:
        return rl_resp

    data = request.get_json() or {}
    mfa_token = data.get("mfa_token", "")
    otp_input = data.get("otp", "").strip()

    session = MFA_SESSIONS.get(mfa_token)
    if not session:
        return jsonify({"error": "Phiên MFA không hợp lệ hoặc đã bị hủy. Vui lòng đăng nhập lại."}), 401

    if time.time() > session["expires"]:
        MFA_SESSIONS.pop(mfa_token, None)
        return jsonify({"error": "Mã OTP đã hết hạn. Vui lòng đăng nhập lại."}), 401

    # Chống Brute-force OTP: Tối đa 3 lần thử cho mỗi mã
    session["attempts"] += 1
    if not hmac.compare_digest(session["otp_hash"], hash_otp(otp_input)):
        remaining = 3 - session["attempts"]
        if remaining <= 0:
            MFA_SESSIONS.pop(mfa_token, None)
            return jsonify({
                "error": "Bạn đã nhập sai OTP 3 lần! Phiên xác thực bị hủy để chống dò mã."
            }), 403
        return jsonify({"error": f"Mã OTP không đúng. Còn {remaining} lần thử."}), 401

    # Xác thực MFA hoàn tất -> Xóa phiên MFA và cấp cặp Token
    username = session["username"]
    MFA_SESSIONS.pop(mfa_token, None)

    access_token, refresh_id, family_id = issue_token_pair(username)
    resp = make_response(jsonify({
        "status": "AUTHENTICATED",
        "access_token": access_token,
        "refresh_token_debug": refresh_id,  # Chỉ hiển thị phục vụ nút bấm Demo Replay Attack
        "family_id": family_id,
        "expires_in": 60
    }))
    # Lưu Refresh Token vào HttpOnly Cookie
    resp.set_cookie(
        "refresh_token",
        refresh_id,
        httponly=True,
        samesite="Strict",
        secure=False,  # Đặt True trên môi trường HTTPS thực tế
        max_age=3600
    )
    return resp


@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    data = request.get_json(silent=True) or {}
    # Hỗ trợ lấy từ Cookie HttpOnly chuẩn hoặc từ tham số giả lập tấn công Replay
    refresh_id = data.get("override_refresh_token") or request.cookies.get("refresh_token")

    if not refresh_id or refresh_id not in REFRESH_TOKENS:
        return jsonify({"error": "Refresh Token không tồn tại hoặc không hợp lệ."}), 401

    rt_record = REFRESH_TOKENS[refresh_id]

    # PHÁT HIỆN TÁI SỬ DỤNG (REUSE DETECTION):
    # Nếu một Refresh Token đã từng được sử dụng (`used == True`) lại bị gửi lên lần nữa
    if rt_record["used"]:
        revoke_token_family(rt_record["family_id"])
        return jsonify({
            "error": "CẢNH BÁO BẢO MẬT: Phát hiện Refresh Token cũ bị tái sử dụng (Token Replay)! Toàn bộ phiên đăng nhập của tài khoản đã bị thu hồi khẩn cấp."
        }), 403

    if rt_record["revoked"] or time.time() > rt_record["expires"]:
        return jsonify({"error": "Refresh Token đã bị thu hồi hoặc hết hạn. Vui lòng đăng nhập lại."}), 401

    # Đánh dấu Refresh Token hiện tại là đã dùng và xoay vòng (Rotation) sang mã mới
    rt_record["used"] = True
    new_access, new_refresh, family_id = issue_token_pair(
        rt_record["username"],
        family_id=rt_record["family_id"]
    )

    resp = make_response(jsonify({
        "status": "ROTATED",
        "access_token": new_access,
        "old_refresh_token": refresh_id,
        "refresh_token_debug": new_refresh,
        "family_id": family_id
    }))
    resp.set_cookie(
        "refresh_token",
        new_refresh,
        httponly=True,
        samesite="Strict",
        secure=False,
        max_age=3600
    )
    return resp


@app.route("/api/profile", methods=["GET"])
@require_auth
def api_profile():
    return jsonify({
        "user": request.user,
        "role": "Security Engineer",
        "message": "Truy cập tài nguyên bảo vệ thành công bằng JWT Access Token!",
        "timestamp": time.strftime("%H:%M:%S")
    })


@app.route("/api/logout", methods=["POST"])
def api_logout():
    refresh_id = request.cookies.get("refresh_token")
    if refresh_id and refresh_id in REFRESH_TOKENS:
        revoke_token_family(REFRESH_TOKENS[refresh_id]["family_id"])
    resp = make_response(jsonify({"message": "Đã đăng xuất và hủy toàn bộ chuỗi Refresh Token."}))
    resp.delete_cookie("refresh_token")
    return resp


# =====================================================================
# 4. GIAO DIỆN DEMO TƯƠNG TÁC (SINGLE-PAGE DASHBOARD)
# =====================================================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <title>Demo App Login An Toàn (MFA + Anti-BruteForce + Token Rotation)</title>
  <style>
    * { box-sizing: border-box; font-family: system-ui, -apple-system, sans-serif; }
    body { margin: 0; padding: 24px; background: #0f172a; color: #f8fafc; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; max-width: 1100px; margin: 0 auto; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; }
    h2 { margin-top: 0; font-size: 18px; color: #38bdf8; }
    label { display: block; font-size: 13px; color: #cbd5e1; margin-bottom: 6px; }
    input { width: 100%; padding: 10px; margin-bottom: 14px; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #fff; }
    button { padding: 10px 14px; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; background: #0284c7; color: white; margin-right: 6px; margin-bottom: 8px; }
    button.secondary { background: #475569; }
    button.danger { background: #dc2626; }
    .sms-box { background: #064e3b; border: 1px solid #10b981; padding: 12px; border-radius: 8px; margin-top: 10px; font-size: 14px; }
    .log-box { background: #020617; border: 1px solid #1e293b; padding: 12px; border-radius: 8px; font-family: monospace; font-size: 12px; height: 240px; overflow-y: auto; white-space: pre-wrap; color: #a7f3d0; }
    .hidden { display: none; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 12px; background: #334155; color: #94a3b8; }
  </style>
</head>
<body>
  <div class="grid">
    <!-- CỘT TRÁI: LUỒNG ĐĂNG NHẬP & MFA -->
    <div class="card">
      <h2>1. Cổng Đăng Nhập Đa Lớp</h2>
      <p style="font-size:13px; color:#94a3b8;">Tài khoản mẫu: <b>vinh_ptit</b> | Mật khẩu: <b>AnToan@2026</b></p>

      <div id="step-login">
        <label>Tên đăng nhập</label>
        <input id="username" value="vinh_ptit" />
        <label>Mật khẩu</label>
        <input id="password" type="password" value="AnToan@2026" />

        <div id="captcha-container" class="hidden">
          <label id="captcha-question" style="color:#fbbf24; font-weight:bold;"></label>
          <input id="captcha-answer" placeholder="Nhập kết quả phép tính CAPTCHA" />
        </div>

        <button onclick="submitLogin()">Đăng nhập (Bước 1)</button>
        <button class="secondary" onclick="testWrongPassword()">Thử sai mật khẩu (Test CAPTCHA/Lockout)</button>
      </div>

      <div id="step-mfa" class="hidden">
        <label style="color:#38bdf8; font-weight:bold;">Bước 2: Nhập mã SMS OTP (6 chữ số)</label>
        <input id="otp-input" placeholder="Nhập 6 số OTP từ hộp thư SMS..." />
        <button onclick="submitOtp()">Xác nhận OTP</button>
        <button class="secondary" onclick="resetFlow()">Quay lại</button>
      </div>

      <h2 style="margin-top:24px;">2. Hộp thư SMS Giả lập (Virtual Phone)</h2>
      <div id="sms-inbox" class="sms-box">Chưa có tin nhắn SMS nào.</div>
    </div>

    <!-- CỘT PHẢI: QUẢN LÝ TOKEN & KIỂM THỬ TẤN CÔNG -->
    <div class="card">
      <h2>3. Quản lý Phiên & Kiểm thử Token Rotation</h2>
      <p style="font-size:13px;">
        Trạng thái: <span id="auth-status" class="badge">Chưa xác thực</span><br><br>
        <b>Access Token (Lưu trên RAM):</b> <span id="access-preview" style="font-family:monospace; font-size:12px; color:#38bdf8;">None</span>
      </p>

      <button onclick="callProtectedApi()">Gọi API /api/profile</button>
      <button onclick="rotateRefreshToken()">Làm mới Token (/api/refresh)</button>
      <button class="danger" onclick="simulateTokenReplay()">Giả lập Đánh cắp & Replay Refresh Token Cũ</button>
      <button class="secondary" onclick="logout()">Đăng xuất</button>

      <h2 style="margin-top:18px;">Nhật ký Phản hồi Bảo mật (Security Logs)</h2>
      <div id="logs" class="log-box">Sẵn sàng kiểm thử...</div>
    </div>
  </div>

<script>
  let accessTokenInMemory = null; // Lưu trên RAM, tuyệt đối không lưu localStorage
  let currentMfaToken = null;
  let currentCaptchaId = null;
  let previousRefreshToken = null; // Lưu lại mã cũ để minh họa tấn công Replay

  function log(title, data) {
    const box = document.getElementById("logs");
    const time = new Date().toLocaleTimeString();
    box.textContent = `[${time}] ${title}:\n${JSON.stringify(data, null, 2)}\n\n` + box.textContent;
  }

  async function submitLogin() {
    const payload = {
      username: document.getElementById("username").value,
      password: document.getElementById("password").value,
      captcha_id: currentCaptchaId,
      captcha_answer: document.getElementById("captcha-answer").value
    };
    const res = await fetch("/api/login", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    log(`POST /api/login (HTTP ${res.status})`, data);

    if (data.require_captcha) {
      currentCaptchaId = data.captcha_id;
      document.getElementById("captcha-container").classList.remove("hidden");
      document.getElementById("captcha-question").textContent = "Xác minh CAPTCHA: " + data.captcha_question;
      document.getElementById("captcha-answer").value = "";
    }

    if (data.status === "MFA_REQUIRED") {
      currentMfaToken = data.mfa_token;
      document.getElementById("step-login").classList.add("hidden");
      document.getElementById("step-mfa").classList.remove("hidden");
      document.getElementById("sms-inbox").innerHTML =
        `<b>Tới:</b> ${data.sms_preview.to} (${data.sms_preview.time})<br>${data.sms_preview.message}`;
    }
  }

  function testWrongPassword() {
    document.getElementById("password").value = "SaiMatKhau123";
    submitLogin();
  }

  async function submitOtp() {
    const res = await fetch("/api/verify-otp", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        mfa_token: currentMfaToken,
        otp: document.getElementById("otp-input").value
      })
    });
    const data = await res.json();
    log(`POST /api/verify-otp (HTTP ${res.status})`, data);

    if (data.status === "AUTHENTICATED") {
      accessTokenInMemory = data.access_token;
      document.getElementById("auth-status").textContent = "Đã xác thực MFA (Family: " + data.family_id + ")";
      document.getElementById("auth-status").style.background = "#059669";
      document.getElementById("auth-status").style.color = "#fff";
      document.getElementById("access-preview").textContent = accessTokenInMemory.slice(0, 36) + "...";
      resetFlow();
    }
  }

  async function callProtectedApi() {
    const res = await fetch("/api/profile", {
      headers: accessTokenInMemory ? {"Authorization": "Bearer " + accessTokenInMemory} : {}
    });
    const data = await res.json();
    log(`GET /api/profile (HTTP ${res.status})`, data);
  }

  async function rotateRefreshToken() {
    const res = await fetch("/api/refresh", { method: "POST" });
    const data = await res.json();
    log(`POST /api/refresh (HTTP ${res.status})`, data);
    if (data.status === "ROTATED") {
      accessTokenInMemory = data.access_token;
      previousRefreshToken = data.old_refresh_token;
      document.getElementById("access-preview").textContent = accessTokenInMemory.slice(0, 36) + "... (Đã xoay vòng)";
    }
  }

  async function simulateTokenReplay() {
    if (!previousRefreshToken) {
      alert("Hãy bấm 'Làm mới Token (/api/refresh)' ít nhất 1 lần trước để tạo ra một Refresh Token cũ!");
      return;
    }
    const res = await fetch("/api/refresh", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ override_refresh_token: previousRefreshToken })
    });
    const data = await res.json();
    log(`ATTACK REPLAY /api/refresh (HTTP ${res.status})`, data);
    if (res.status === 403) {
      document.getElementById("auth-status").textContent = "Phiên bị thu hồi khẩn cấp (Phát hiện Replay!)";
      document.getElementById("auth-status").style.background = "#dc2626";
    }
  }

  async function logout() {
    const res = await fetch("/api/logout", { method: "POST" });
    const data = await res.json();
    accessTokenInMemory = null;
    previousRefreshToken = null;
    document.getElementById("auth-status").textContent = "Đã đăng xuất";
    document.getElementById("auth-status").style.background = "#334155";
    document.getElementById("access-preview").textContent = "None";
    log(`POST /api/logout (HTTP ${res.status})`, data);
  }

  function resetFlow() {
    document.getElementById("step-login").classList.remove("hidden");
    document.getElementById("step-mfa").classList.add("hidden");
    document.getElementById("captcha-container").classList.add("hidden");
    document.getElementById("otp-input").value = "";
  }
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

if __name__ == "__main__":
    print("Khởi chạy Demo App Login An Toàn tại: http://127.0.0.1:5000")
    app.run(debug=True, port=5000)