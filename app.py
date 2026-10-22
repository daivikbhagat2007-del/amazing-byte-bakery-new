from dotenv import load_dotenv
load_dotenv()
import os, re, hmac, hashlib, json
from decimal import Decimal
from functools import wraps
import click, razorpay
import mysql.connector.pooling
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    SESSION_COOKIE_SECURE=os.environ.get("PRODUCTION") == "1",
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=64 * 1024)
csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address, app=app)

# ---------- database ----------
_pool = None

def conn():
    global _pool
    if _pool is None:
        _pool = mysql.connector.pooling.MySQLConnectionPool(
            pool_name="p",
            pool_size=5,
            host=os.environ["DB_HOST"],
            port=int(os.environ.get("DB_PORT", 4000)),
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASSWORD"],
            database=os.environ.get("DB_NAME", "bakery_db"),
            ssl_ca=os.path.join(
                os.path.dirname(__file__), "certs", "isrgrootx1.pem"
            ),
            ssl_verify_cert=True,
            ssl_verify_identity=True
        )
    return _pool.get_connection()

def db(sql, args=(), one=False, write=False):
    c = conn()
    try:
        cur = c.cursor(dictionary=True)
        cur.execute(sql, args)
        if write:
            c.commit(); return cur.lastrowid
        return cur.fetchone() if one else cur.fetchall()
    finally:
        c.close()

class tx:
    def __enter__(self):
        self.c = conn(); self.c.start_transaction()
        self.cur = self.c.cursor(dictionary=True); return self.cur
    def __exit__(self, t, v, tb):
        self.c.rollback() if t else self.c.commit()
        self.c.close()

SCHEMA = [
"""CREATE TABLE IF NOT EXISTS users(id INT AUTO_INCREMENT PRIMARY KEY, full_name VARCHAR(100) NOT NULL,
 email VARCHAR(190) NOT NULL UNIQUE, phone VARCHAR(15) NOT NULL, password_hash VARCHAR(255) NOT NULL,
 role ENUM('customer','admin') NOT NULL DEFAULT 'customer', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""",
"CREATE TABLE IF NOT EXISTS categories(id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(80) NOT NULL UNIQUE)",
"""CREATE TABLE IF NOT EXISTS cakes(id INT AUTO_INCREMENT PRIMARY KEY, category_id INT NOT NULL, name VARCHAR(120) NOT NULL,
 description TEXT, price DECIMAL(10,2) NOT NULL, image_url VARCHAR(500), available TINYINT(1) NOT NULL DEFAULT 1,
 FOREIGN KEY(category_id) REFERENCES categories(id))""",
"""CREATE TABLE IF NOT EXISTS addresses(id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, line1 VARCHAR(255) NOT NULL,
 city VARCHAR(80) NOT NULL, pincode CHAR(6) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id))""",
"""CREATE TABLE IF NOT EXISTS orders(id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, address_id INT NOT NULL,
 total DECIMAL(10,2) NOT NULL, status ENUM('awaiting_payment','placed','confirmed','baking','out_for_delivery','delivered','cancelled') NOT NULL,
 payment_method ENUM('cod','online') NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(address_id) REFERENCES addresses(id))""",
"""CREATE TABLE IF NOT EXISTS order_items(id INT AUTO_INCREMENT PRIMARY KEY, order_id INT NOT NULL, cake_id INT NOT NULL,
 name VARCHAR(120) NOT NULL, price DECIMAL(10,2) NOT NULL, qty INT NOT NULL,
 FOREIGN KEY(order_id) REFERENCES orders(id), FOREIGN KEY(cake_id) REFERENCES cakes(id))""",
"""CREATE TABLE IF NOT EXISTS payments(id INT AUTO_INCREMENT PRIMARY KEY, order_id INT NOT NULL, method ENUM('cod','online') NOT NULL,
 gateway_order_id VARCHAR(64) UNIQUE, gateway_payment_id VARCHAR(64) UNIQUE, amount DECIMAL(10,2) NOT NULL,
 status ENUM('pending','successful','failed','refunded') NOT NULL DEFAULT 'pending',
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(order_id) REFERENCES orders(id))""",
"""CREATE TABLE IF NOT EXISTS contact_messages(
 id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(150) NOT NULL,
 message TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""",
]
SEED = {"Birthday Cakes": [("Classic Vanilla Birthday Cake", "Soft vanilla sponge with buttercream, 1 kg.", 750),
                           ("Strawberry Birthday Cake", "Fresh strawberry cream layers, 1 kg.", 850)],
        "Chocolate Cakes": [("Dark Chocolate Truffle", "Rich ganache over moist chocolate sponge, 1 kg.", 900),
                            ("Chocolate Fudge Cake", "Fudgy layers, 500 g.", 500)],
        "Pastries": [("Black Forest Pastry", "Cherry, cream and chocolate shavings.", 90),
                     ("Pineapple Pastry", "Light sponge with pineapple cream.", 80)],
        "Cupcakes": [("Vanilla Cupcake (box of 4)", "Buttercream-topped cupcakes.", 220),
                     ("Chocolate Cupcake (box of 4)", "Chocolate cupcakes with ganache.", 260)],
        "Custom Cakes": [("Custom Photo/Theme Cake", "Tell us your design in the order; we will confirm by phone. Price is a starting price.", 1200)]}

@app.cli.command("init-db")
def init_db():
    c = conn(); cur = c.cursor()
    for s in SCHEMA: cur.execute(s)
    cur.execute("SELECT COUNT(*) FROM categories")
    if cur.fetchone()[0] == 0:
        for cat, cakes in SEED.items():
            cur.execute("INSERT INTO categories(name) VALUES(%s)", (cat,)); cid = cur.lastrowid
            for n, d, p in cakes:
                cur.execute("INSERT INTO cakes(category_id,name,description,price) VALUES(%s,%s,%s,%s)", (cid, n, d, p))
    c.commit(); c.close(); print("Database ready.")

@app.cli.command("create-admin")
@click.option("--email", prompt=True)
@click.option("--name", prompt=True)
@click.password_option()
def create_admin(email, name, password):
    if len(password) < 12: raise click.ClickException("Use at least 12 characters.")
    u = db("SELECT id FROM users WHERE email=%s", (email.lower(),), one=True)
    if u: db("UPDATE users SET role='admin', password_hash=%s WHERE id=%s", (generate_password_hash(password), u["id"]), write=True)
    else: db("INSERT INTO users(full_name,email,phone,password_hash,role) VALUES(%s,%s,'0000000000',%s,'admin')",
             (name, email.lower(), generate_password_hash(password)), write=True)
    print("Admin ready.")

# ---------- helpers ----------
def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("uid"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*a, **k)
    return w

def admin_required(f):
    @login_required
    @wraps(f)
    def w(*a, **k):
        u = db("SELECT role FROM users WHERE id=%s", (session["uid"],), one=True)
        if not u or u["role"] != "admin": abort(403)
        return f(*a, **k)
    return w

@app.context_processor
def inject():
    u = db("SELECT full_name, role FROM users WHERE id=%s", (session["uid"],), one=True) if session.get("uid") else None
    return dict(user=u, cart_count=sum(session.get("cart", {}).values()))

def cart_items():
    cart = session.get("cart", {})
    if not cart: return [], Decimal(0)
    ids = [int(i) for i in cart]
    rows = db("SELECT * FROM cakes WHERE available=1 AND id IN (%s)" % ",".join(["%s"] * len(ids)), ids)
    total = Decimal(0)
    for r in rows:
        r["qty"] = cart[str(r["id"])]; r["line"] = r["price"] * r["qty"]; total += r["line"]
    return rows, total

def rz():
    return razorpay.Client(auth=(os.environ["RAZORPAY_KEY_ID"], os.environ["RAZORPAY_KEY_SECRET"]))

def mark_paid(gateway_order_id, payment_id):
    with tx() as cur:
        cur.execute("SELECT id, order_id, status FROM payments WHERE gateway_order_id=%s FOR UPDATE", (gateway_order_id,))
        p = cur.fetchone()
        if not p or p["status"] == "successful": return bool(p)
        cur.execute("UPDATE payments SET status='successful', gateway_payment_id=%s WHERE id=%s", (payment_id, p["id"]))
        cur.execute("UPDATE orders SET status='placed' WHERE id=%s AND status='awaiting_payment'", (p["order_id"],))
    return True

@app.errorhandler(403)
def e403(e): return "Forbidden", 403
@app.errorhandler(500)
def e500(e): return "Something went wrong. Please try again.", 500

# ---------- storefront ----------
@app.route("/")
def index():
    q = request.args.get("q", "").strip(); cat = request.args.get("category", type=int)
    sql, args = "SELECT c.*, k.name AS category FROM cakes c JOIN categories k ON k.id=c.category_id WHERE 1=1", []
    if q: sql += " AND (c.name LIKE %s OR c.description LIKE %s)"; args += [f"%{q}%"] * 2
    if cat: sql += " AND c.category_id=%s"; args.append(cat)
    return render_template("index.html", cakes=db(sql + " ORDER BY c.available DESC, c.name", args),
                           categories=db("SELECT * FROM categories ORDER BY name"), q=q, cat=cat)

@app.route("/cart")
def cart():
    items, total = cart_items(); return render_template("cart.html", items=items, total=total)

@app.post("/cart/set")
def cart_set():
    cid = request.form.get("cake_id", type=int); qty = request.form.get("qty", type=int, default=1)
    mode = request.form.get("mode", "set"); c = session.get("cart", {})
    if not cid or not db("SELECT id FROM cakes WHERE id=%s AND available=1", (cid,), one=True):
        flash("That item is unavailable.", "warning"); return redirect(request.referrer or url_for("index"))
    new = (c.get(str(cid), 0) if mode == "add" else 0) + (qty or 0)
    if new <= 0: c.pop(str(cid), None)
    else: c[str(cid)] = min(new, 20)
    session["cart"] = c
    return redirect(url_for("cart") if mode == "set" else (request.referrer or url_for("index")))

# ---------- auth ----------
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10/hour", methods=["POST"])
def register():
    if request.method == "POST":
        f = request.form; e = []
        name, email, phone = f.get("full_name", "").strip(), f.get("email", "").strip().lower(), re.sub(r"\D", "", f.get("phone", ""))[-10:]
        line, city, pin, pw = f.get("line1", "").strip(), f.get("city", "").strip(), f.get("pincode", "").strip(), f.get("password", "")
        if len(name) < 2: e.append("Enter your full name.")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email): e.append("Enter a valid email.")
        if not re.fullmatch(r"[6-9]\d{9}", phone): e.append("Enter a valid 10-digit Indian mobile number.")
        if not line or not city or not re.fullmatch(r"\d{6}", pin): e.append("Enter address, city and a 6-digit pincode.")
        if len(pw) < 8: e.append("Password must be at least 8 characters.")
        if not e and db("SELECT id FROM users WHERE email=%s", (email,), one=True): e.append("That email is already registered.")
        if not e:
            try:
                with tx() as cur:
                    cur.execute("INSERT INTO users(full_name,email,phone,password_hash) VALUES(%s,%s,%s,%s)", (name, email, phone, generate_password_hash(pw)))
                    uid = cur.lastrowid
                    cur.execute("INSERT INTO addresses(user_id,line1,city,pincode) VALUES(%s,%s,%s,%s)", (uid, line, city, pin))
            except mysql.connector.IntegrityError:
                e.append("That email is already registered.")
            else:
                session.clear(); session["uid"] = uid; flash("Welcome to Amazing Byte Bakery!", "success"); return redirect(url_for("index"))
        for m in e: flash(m, "danger")
        return render_template("register.html", f=f)
    return render_template("register.html", f={})

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10/minute", methods=["POST"])
def login():
    if request.method == "POST":
        u = db("SELECT id, password_hash FROM users WHERE email=%s", (request.form.get("email", "").strip().lower(),), one=True)
        if u and check_password_hash(u["password_hash"], request.form.get("password", "")):
            cart_ = session.get("cart", {}); session.clear(); session["uid"] = u["id"]; session["cart"] = cart_
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("index"))
        flash("Incorrect email or password.", "danger")
    return render_template("login.html")

@app.post("/logout")
def logout():
    session.clear(); return redirect(url_for("index"))

# ---------- checkout & payment ----------
@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    items, total = cart_items()
    if not items: return redirect(url_for("cart"))
    uid = session["uid"]
    last = db("SELECT line1, city, pincode FROM addresses WHERE user_id=%s ORDER BY id DESC LIMIT 1", (uid,), one=True) or {}
    if request.method == "POST":
        f = request.form; line, city, pin, method = f.get("line1", "").strip(), f.get("city", "").strip(), f.get("pincode", "").strip(), f.get("method")
        e = []
        if not line or not city or not re.fullmatch(r"\d{6}", pin): e.append("Enter address, city and a 6-digit pincode.")
        if method not in ("cod", "online"): e.append("Choose a payment method.")
        if e:
            for m in e: flash(m, "danger")
            return render_template("checkout.html", items=items, total=total, a=f)
        with tx() as cur:
            cur.execute("INSERT INTO addresses(user_id,line1,city,pincode) VALUES(%s,%s,%s,%s)", (uid, line, city, pin)); aid = cur.lastrowid
            cur.execute("INSERT INTO orders(user_id,address_id,total,status,payment_method) VALUES(%s,%s,%s,%s,%s)",
                        (uid, aid, total, "awaiting_payment" if method == "online" else "placed", method)); oid = cur.lastrowid
            for i in items:
                cur.execute("INSERT INTO order_items(order_id,cake_id,name,price,qty) VALUES(%s,%s,%s,%s,%s)", (oid, i["id"], i["name"], i["price"], i["qty"]))
            cur.execute("INSERT INTO payments(order_id,method,amount,status) VALUES(%s,%s,%s,'pending')", (oid, method, total))
        if method == "online":
            try:
                ro = rz().order.create({"amount": int(total * 100), "currency": "INR", "receipt": f"ABB{oid}"})
                db("UPDATE payments SET gateway_order_id=%s WHERE order_id=%s", (ro["id"], oid), write=True)
            except Exception:
                app.logger.exception("razorpay order create failed")
                db("UPDATE orders SET status='cancelled' WHERE id=%s", (oid,), write=True)
                db("UPDATE payments SET status='failed' WHERE order_id=%s", (oid,), write=True)
                flash("Online payment is unavailable right now. Please try Cash on Delivery.", "danger")
                return redirect(url_for("checkout"))
            session["cart"] = {}; return redirect(url_for("payment", order_id=oid))
        session["cart"] = {}; flash(f"Order #{oid} confirmed. Pay cash on delivery.", "success"); return redirect(url_for("orders"))
    return render_template("checkout.html", items=items, total=total, a=last)

@app.route("/payment/<int:order_id>")
@login_required
def payment(order_id):
    o = db("""SELECT o.id, o.total, p.gateway_order_id FROM orders o JOIN payments p ON p.order_id=o.id
              WHERE o.id=%s AND o.user_id=%s AND o.status='awaiting_payment' AND p.status='pending' AND p.method='online'""",
           (order_id, session["uid"]), one=True)
    if not o: abort(404)
    return render_template("payment.html", o=o, key_id=os.environ["RAZORPAY_KEY_ID"], paise=int(o["total"] * 100))

@app.post("/payment/verify")
@login_required
def payment_verify():
    f = request.form; gid, pid, sig = f.get("razorpay_order_id", ""), f.get("razorpay_payment_id", ""), f.get("razorpay_signature", "")
    p = db("""SELECT p.amount, p.status FROM payments p JOIN orders o ON o.id=p.order_id
              WHERE p.gateway_order_id=%s AND o.user_id=%s""", (gid, session["uid"]), one=True)
    if not p: abort(404)
    try:
        rz().utility.verify_payment_signature({"razorpay_order_id": gid, "razorpay_payment_id": pid, "razorpay_signature": sig})
        gp = rz().payment.fetch(pid)
    except Exception:
        app.logger.warning("payment verification failed for %s", gid)
        flash("We could not verify your payment. If money was debited, it will be reconciled automatically.", "danger")
        return redirect(url_for("orders"))
    if gp.get("order_id") == gid and gp.get("amount") == int(p["amount"] * 100) and gp.get("status") == "captured":
        mark_paid(gid, pid); flash("Payment received. Your order is confirmed!", "success")
    else:
        flash("Payment is pending confirmation. Your order will update shortly.", "warning")
    return redirect(url_for("orders"))

@app.post("/webhooks/razorpay")
@csrf.exempt
def webhook():
    body = request.get_data(); sig = request.headers.get("X-Razorpay-Signature", "")
    good = hmac.new(os.environ["RAZORPAY_WEBHOOK_SECRET"].encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(good, sig): abort(400)
    ev = json.loads(body); ent = ev.get("payload", {}).get("payment", {}).get("entity", {})
    gid, pid = ent.get("order_id"), ent.get("id")
    if ev.get("event") == "payment.captured" and gid:
        mark_paid(gid, pid)
    elif ev.get("event") == "payment.failed" and gid:
        db("UPDATE payments SET status='failed' WHERE gateway_order_id=%s AND status='pending'", (gid,), write=True)
    return jsonify(ok=True)

@app.route("/orders")
@login_required
def orders():
    os_ = db("""SELECT o.*, p.status AS pay_status, a.line1, a.city, a.pincode FROM orders o
                JOIN payments p ON p.order_id=o.id JOIN addresses a ON a.id=o.address_id
                WHERE o.user_id=%s ORDER BY o.id DESC""", (session["uid"],))
    for o in os_: o["items"] = db("SELECT name, price, qty FROM order_items WHERE order_id=%s", (o["id"],))
    return render_template("orders.html", orders=os_)

# ---------- admin ----------
@app.route("/admin")
@admin_required
def admin():
    return render_template("admin.html",
        users=db("SELECT id, full_name, email, phone, role, created_at FROM users ORDER BY id DESC"),
        orders=db("""SELECT o.id, o.total, o.status, o.payment_method, p.status AS pay_status, u.full_name, u.phone,
                     a.line1, a.city, a.pincode FROM orders o JOIN users u ON u.id=o.user_id JOIN payments p ON p.order_id=o.id
                     JOIN addresses a ON a.id=o.address_id ORDER BY o.id DESC LIMIT 200"""),
        cakes=db("SELECT c.*, k.name AS category FROM cakes c JOIN categories k ON k.id=c.category_id ORDER BY c.id"),
        categories=db("SELECT * FROM categories ORDER BY name"),
        statuses=["awaiting_payment", "placed", "confirmed", "baking", "out_for_delivery", "delivered", "cancelled"])

def valid_img(u): return not u or re.fullmatch(r"https://[^\s]+", u)

@app.post("/admin/<action>")
@admin_required
def admin_action(action):
    f = request.form
    try:
        if action == "category":
            db("INSERT INTO categories(name) VALUES(%s)", (f["name"].strip(),), write=True)
        elif action in ("cake_add", "cake_edit"):
            price = Decimal(f["price"]); img = f.get("image_url", "").strip()
            if price <= 0 or not valid_img(img): raise ValueError
            vals = (f["name"].strip(), f.get("description", "").strip(), price, img or None, 1 if f.get("available") else 0)
            if action == "cake_add":
                db("INSERT INTO cakes(name,description,price,image_url,available,category_id) VALUES(%s,%s,%s,%s,%s,%s)", vals + (int(f["category_id"]),), write=True)
            else:
                db("UPDATE cakes SET name=%s, description=%s, price=%s, image_url=%s, available=%s WHERE id=%s", vals + (int(f["id"]),), write=True)
        elif action == "order_status":
            db("UPDATE orders SET status=%s WHERE id=%s", (f["status"], int(f["id"])), write=True)
        elif action == "pay_status":
            if f["status"] not in ("pending", "successful", "failed", "refunded"): raise ValueError
            # Online payments become 'successful' only via verified gateway data; admin may mark refunded/COD collected.
            db("UPDATE payments SET status=%s WHERE order_id=%s AND (method='cod' OR %s IN ('refunded','failed'))", (f["status"], int(f["id"]), f["status"]), write=True)
        else: abort(404)
        flash("Saved.", "success")
    except (ValueError, KeyError, ArithmeticError, mysql.connector.Error):
        flash("Invalid input or duplicate entry.", "danger")
    return redirect(url_for("admin"))
@app.route("/contact", methods=["GET", "POST"])
@limiter.limit("10/hour", methods=["POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:100]
        email = request.form.get("email", "").strip().lower()[:150]
        message = request.form.get("message", "").strip()

        if (name and re.fullmatch(r"[^@\\s]+@[^@\\s]+\\.[^@\\s]+", email)
                and message and len(message) <= 5000):
            db(
                "INSERT INTO contact_messages (name, email, message) VALUES (%s, %s, %s)",
                (name, email, message),
                write=True
            )
            flash("Your message has been sent successfully!", "success")
            return redirect(url_for("contact"))

        flash("Enter a valid name and email, and a message under 5000 characters.", "danger")

    return render_template("contact.html")