# app.py — Flask + PostgreSQL + LinkedIn OAuth (SADECE LinkedIn Login/Register)
# Özellikler:
# - Sadece LinkedIn ile oturum: /auth/linkedin/start → /auth/linkedin/callback
# - İlk girişte kullanıcıyı oluşturur; sonraki girişlerde linkedin_id ile eşler
# - Ad, soyad, e‑posta, profil fotoğrafı saklanır
# - Bakım modu (MAINTENANCE_MODE=1) ve bypass korunur
# - Eski /login ve /create rotaları KAPALI (404 döner)

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    jsonify, abort, make_response
)
import os, random, colorsys, re, time, secrets, string
import psycopg2
from psycopg2.extras import RealDictCursor
from collections import defaultdict
import requests
from urllib.parse import urlencode

###############################################################################
# Ortam değişkeni yardımcı
###############################################################################
def env(key, default=None):
    v = os.environ.get(key)
    return v if v not in (None, "") else default

###############################################################################
# App ve güvenlik
###############################################################################
app = Flask(__name__)
app.secret_key = env("FLASK_SECRET_KEY", "super-secret-key")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
if env("SESSION_COOKIE_SECURE", "0") == "1":
    app.config["SESSION_COOKIE_SECURE"] = True

###############################################################################
# Bakım modu
###############################################################################
MAINTENANCE_COOKIE = "mm_bypass"

def maintenance_active():
    return env("MAINTENANCE_MODE", "0") == "1"

def maintenance_allowed_ip(remote_ip: str) -> bool:
    allow = env("MAINTENANCE_ALLOW_IPS", "")
    allowed_ips = [ip.strip() for ip in allow.split(",") if ip.strip()]
    return remote_ip in allowed_ips

def maintenance_bypass_ok():
    token = env("MAINTENANCE_BYPASS_TOKEN", "")
    if not token:
        return False
    return request.cookies.get(MAINTENANCE_COOKIE) == token

###############################################################################
# LinkedIn OAuth 2.0 ayarları
###############################################################################
LINKEDIN_CLIENT_ID = env("LINKEDIN_CLIENT_ID", "")
LINKEDIN_CLIENT_SECRET = env("LINKEDIN_CLIENT_SECRET", "")
LINKEDIN_REDIRECT_URI = env("LINKEDIN_REDIRECT_URI", "")  # https://enfekte.co/auth/linkedin/callback
LINKEDIN_AUTH_URL = "https://www.linkedin.com/oauth/v2/authorization"
LINKEDIN_TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
ME_URL = "https://api.linkedin.com/v2/me"
EMAIL_URL = "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))"
ME_PROJECTION = "(id,localizedFirstName,localizedLastName,profilePicture(displayImage~:playableStreams))"
SCOPES = ["r_liteprofile", "r_emailaddress"]

def _rand_state(n=24):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))

###############################################################################
# Yardımcılar
###############################################################################
def slugify(text):
    mapping = {
        'ç': 'c', 'ğ': 'g', 'ı': 'i', 'ö': 'o', 'ş': 's', 'ü': 'u',
        'Ç': 'c', 'Ğ': 'g', 'İ': 'i', 'Ö': 'o', 'Ş': 's', 'Ü': 'u'
    }
    for src, target in mapping.items():
        text = text.replace(src, target)
    text = text.lower()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'\s+', '-', text)
    return text.strip('-')

def normalize_name(name):
    mapping = {
        'ç': 'c', 'ğ': 'g', 'ı': 'i', 'ö': 'o', 'ş': 's', 'ü': 'u',
        'Ç': 'c', 'Ğ': 'g', 'İ': 'i', 'Ö': 'o', 'Ş': 's', 'Ü': 'u',
        'I': 'i'
    }
    for src, target in mapping.items():
        name = name.replace(src, target)
    return name.lower().strip()

###############################################################################
# DB bağlantısı ve şema
###############################################################################
def get_db_connection():
    return psycopg2.connect(
        dbname=env("PGDATABASE", "railway"),
        user=env("PGUSER", "postgres"),
        password=env("PGPASSWORD", "CHANGE_ME_IN_ENV"),
        host=env("PGHOST", "localhost"),
        port=env("PGPORT", "5432"),
        cursor_factory=RealDictCursor
    )

def init_db():
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    name TEXT,
                    slug TEXT UNIQUE,
                    linkedin_id TEXT UNIQUE,
                    email TEXT,
                    photo_url TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS connections (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    visitor_name TEXT,
                    connection_type TEXT,
                    connector_name TEXT,
                    visitor_id INTEGER REFERENCES users(id),
                    connector_id INTEGER REFERENCES users(id)
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_users_slug ON users(slug)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_users_linkedin ON users(linkedin_id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_connections_owner ON connections(owner_id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_connections_visitor_name ON connections(visitor_name)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_connections_connector_name ON connections(connector_name)")
        conn.commit()

###############################################################################
# Görselleştirme yardımcıları
###############################################################################
def random_color():
    h, s, v = random.random(), 0.5 + random.random() * 0.5, 0.7 + random.random() * 0.3
    r, g, b = colorsys.hsv_to_rgb(h, s, v)
    return f'rgb({int(r*255)}, {int(g*255)}, {int(b*255)})'

def mix_colors(colors):
    if not colors:
        return "#cccccc"
    total_r = total_g = total_b = valid_count = 0
    for col in colors:
        try:
            if col.startswith("rgb(") and col.endswith(")"):
                r, g, b = map(int, col[4:-1].split(','))
                total_r += r; total_g += g; total_b += b
                valid_count += 1
        except Exception:
            continue
    if valid_count == 0:
        return "#cccccc"
    avg_r = total_r // valid_count
    avg_g = total_g // valid_count
    avg_b = total_b // valid_count
    return f"rgb({avg_r}, {avg_g}, {avg_b})'

def fixed_color(user_id):
    palette = [
        "#4CAF50", "#81C784", "#66BB6A", "#388E3C", "#2E7D32",
        "#1B5E20", "#A5D6A7", "#43A047", "#00796B", "#33691E"
    ]
    return palette[user_id % len(palette)]

def build_graph_multi(rows, user_rows):
    owner_to_rows = defaultdict(list)
    for row in rows:
        if 'owner_id' in row:
            owner_to_rows[row['owner_id']].append((row['visitor_name'], row['connection_type'], row.get('connector_name')))
    user_id_to_name = {u['id']: u['name'] for u in user_rows}
    user_name_to_slug = {u['name']: u['slug'] for u in user_rows}
    user_id_to_color = {u['id']: fixed_color(u['id']) for u in user_rows}

    name_to_owners = defaultdict(set)
    all_edges = set()

    for owner_id, conns in owner_to_rows.items():
        owner_name = user_id_to_name.get(owner_id, f"user_{owner_id}")
        name_to_connector = {v: (t, c) for v, t, c in conns}
        for visitor in name_to_connector:
            person, chain = visitor, []
            while True:
                ctype, connector = name_to_connector.get(person, (None, None))
                if connector and connector != person:
                    chain.append((person, connector))
                    person = connector
                else:
                    break
            if chain:
                all_edges.add((chain[-1][1], owner_name))
            else:
                all_edges.add((visitor, owner_name))
            all_edges.update(chain)
            for n in [visitor] + [c for _, c in chain] + [owner_name]:
                name_to_owners[n].add(owner_id)

    all_nodes = {n for edge in all_edges for n in edge}
    name_to_id = {name: i + 1 for i, name in enumerate(sorted(all_nodes))}

    nodes_vis = []
    for name, nid in name_to_id.items():
        owners = name_to_owners.get(name, set())
        colors = [user_id_to_color[o] for o in owners if o in user_id_to_color]
        color = colors[0] if len(colors) == 1 else mix_colors(colors)
        node = {"id": nid, "label": name, "color": color}
        if name in user_name_to_slug:
            node["slug"] = user_name_to_slug[name]
        nodes_vis.append(node)

    edges_vis = [{"from": name_to_id[f], "to": name_to_id[t]} for f, t in all_edges]
    return nodes_vis, edges_vis

###############################################################################
# CSRF (sadece gerekli POST'lar için; form tabanlı login yok)
###############################################################################
def ensure_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(16)

def validate_csrf():
    token = request.form.get("csrf_token")
    if not token or token != session.get("csrf_token"):
        abort(400, description="Geçersiz CSRF token")

###############################################################################
# Global maintenance guard
###############################################################################
@app.before_request
def _pre():
    ensure_csrf_token()
    open_paths = (
        "/healthz",
        "/__maintenance-bypass",
        "/maintenance",
        "/favicon.ico",
        "/robots.txt",
        "/auth/linkedin/start",
        "/auth/linkedin/callback",
    )
    if request.path.startswith("/static/") or request.path in open_paths:
        return

    if maintenance_active():
        if maintenance_allowed_ip(request.remote_addr) or maintenance_bypass_ok():
            return
        resp = make_response(render_template("maintenance.html"), 503)
        resp.headers["Retry-After"] = "3600"
        return resp

###############################################################################
# LinkedIn OAuth akışı
###############################################################################
@app.get("/auth/linkedin/start")
def linkedin_start():
    if not LINKEDIN_CLIENT_ID or not LINKEDIN_REDIRECT_URI:
        return "LinkedIn OAuth yapılandırılmamış. Env değişkenlerini kontrol edin.", 500

    state = _rand_state()
    session["li_oauth_state"] = state

    params = {
        "response_type": "code",
        "client_id": LINKEDIN_CLIENT_ID,
        "redirect_uri": LINKEDIN_REDIRECT_URI,
        "state": state,
        "scope": " ".join(SCOPES),
    }
    return redirect(f"{LINKEDIN_AUTH_URL}?{urlencode(params)}")

@app.get("/auth/linkedin/callback")
def linkedin_callback():
    if request.args.get("error"):
        return f"LinkedIn hata: {request.args.get('error_description','error')}", 400

    code = request.args.get("code")
    state = request.args.get("state")
    if not code or not state or state != session.get("li_oauth_state"):
        return "Geçersiz veya eksik yetkilendirme cevabı.", 400

    # Access token
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": LINKEDIN_REDIRECT_URI,
        "client_id": LINKEDIN_CLIENT_ID,
        "client_secret": LINKEDIN_CLIENT_SECRET,
    }
    token_resp = requests.post(LINKEDIN_TOKEN_URL, data=data, timeout=15)
    if token_resp.status_code != 200:
        return f"Token alınamadı: {token_resp.text}", 400
    access_token = token_resp.json().get("access_token")
    if not access_token:
        return "Erişim tokeni bulunamadı.", 400

    headers = {"Authorization": f"Bearer {access_token}"}
    # Profil
    me = requests.get(ME_URL, params={"projection": ME_PROJECTION}, headers=headers, timeout=15).json()
    # E‑posta
    email_addr = None
    try:
        ej = requests.get(EMAIL_URL, headers=headers, timeout=15).json()
        email_addr = ej["elements"][0]["handle~"]["emailAddress"]
    except Exception:
        email_addr = None

    linkedin_id = me.get("id")
    first = me.get("localizedFirstName", "") or ""
    last = me.get("localizedLastName", "") or ""
    full_name = f"{first} {last}".strip() or "LinkedIn User"

    # Foto URL
    photo_url = None
    try:
        display = me.get("profilePicture", {}).get("displayImage~", {})
        elements = display.get("elements", [])
        if elements:
            variants = elements[-1].get("identifiers", [])
            if variants:
                photo_url = variants[0].get("identifier")
    except Exception:
        photo_url = None

    if not linkedin_id:
        return "LinkedIn ID alınamadı.", 400

    # Kullanıcı oluştur/güncelle
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("SELECT id, slug FROM users WHERE linkedin_id = %s", (linkedin_id,))
            existing = c.fetchone()
            if existing:
                user_id = existing["id"]
                c.execute("""
                    UPDATE users SET name=%s, email=%s, photo_url=%s WHERE id=%s
                """, (full_name, email_addr, photo_url, user_id))
                conn.commit()
                session["user_id"] = user_id
                return redirect(url_for("edit_page", slug=existing["slug"]))
            else:
                base_slug = slugify(full_name or f"user-{linkedin_id}")
                slug = base_slug
                n = 1
                while True:
                    c.execute("SELECT 1 FROM users WHERE slug=%s", (slug,))
                    if c.fetchone():
                        n += 1
                        slug = f"{base_slug}-{n}"
                    else:
                        break
                c.execute("""
                    INSERT INTO users (name, slug, linkedin_id, email, photo_url)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                """, (full_name, slug, linkedin_id, email_addr, photo_url))
                user_id = c.fetchone()["id"]
                conn.commit()
                session["user_id"] = user_id
                return redirect(url_for("edit_page", slug=slug))

###############################################################################
# Bakım bypass ve health
###############################################################################
@app.get("/__maintenance-bypass")
def maintenance_bypass():
    token = env("MAINTENANCE_BYPASS_TOKEN", "")
    given = request.args.get("token", "")
    if not token:
        return "BYPASS devre dışı (MAINTENANCE_BYPASS_TOKEN ayarlanmadı).", 400
    if given != token:
        return "Geçersiz token.", 403
    resp = make_response("Baypas aktif. Çerez set edildi.")
    resp.set_cookie(MAINTENANCE_COOKIE, token,
                    httponly=True,
                    samesite="Lax",
                    secure=app.config.get("SESSION_COOKIE_SECURE", False),
                    max_age=60*60*3)
    return resp

@app.get("/maintenance")
def maintenance_page_direct():
    return render_template("maintenance.html"), 503

@app.get("/healthz")
def healthz():
    return "ok", 200

###############################################################################
# Uygulama rotaları
###############################################################################
@app.route('/')
def home():
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("SELECT * FROM connections")
            conn_rows = c.fetchall()
            c.execute("SELECT id, name, slug FROM users")
            user_rows = c.fetchall()
    nodes, edges = build_graph_multi(conn_rows, user_rows)
    return render_template("home.html", nodes=nodes, edges=edges)

# ---- SADECE LinkedIn login olduğundan geleneksel /create ve /login kapalı:
@app.route('/create', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
@app.route('/login/<slug>', methods=['GET', 'POST'])
def disabled_auth_routes(slug=None):
    return "Bu uygulamada giriş ve kayıt sadece LinkedIn ile yapılır.", 404

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/<slug>', methods=['GET', 'POST'])
def user_page(slug):
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("SELECT id, name FROM users WHERE slug = %s", (slug,))
            user = c.fetchone()
            if not user:
                return "Kullanıcı bulunamadı", 404
            owner_id, owner_name = user['id'], user['name']

            if request.method == 'POST' and session.get('user_id') != owner_id:
                validate_csrf()
                visitor_name = request.form['name'].strip()
                connection_type = request.form['type'].strip()
                connector_name = request.form.get('connector', '').strip() or None
                if len(visitor_name) < 2:
                    return "Ziyaretçi adı çok kısa.", 400

                now = time.time()
                key = f"last_post_{request.remote_addr}"
                last = session.get(key, 0)
                if now - last < 3:
                    return "Çok hızlı istek. Lütfen tekrar deneyin.", 429
                session[key] = now

                c.execute("SELECT visitor_name FROM connections WHERE owner_id = %s", (owner_id,))
                existing = [normalize_name(row['visitor_name']) for row in c.fetchall()]
                if normalize_name(visitor_name) in existing:
                    return f"{visitor_name} zaten eklenmiş.", 409

                c.execute(
                    "INSERT INTO connections (owner_id, visitor_name, connection_type, connector_name) VALUES (%s, %s, %s, %s)",
                    (owner_id, visitor_name, connection_type, connector_name)
                )
                conn.commit()
                return redirect(url_for('user_page', slug=slug))

            c.execute("""
                SELECT * FROM connections 
                WHERE owner_id = %s OR visitor_name = %s OR connector_name = %s
            """, (owner_id, owner_name, owner_name))
            rows = c.fetchall()

            c.execute("SELECT id, name, slug FROM users")
            user_rows = c.fetchall()

    nodes_vis, edges_vis = build_graph_multi(rows, user_rows)
    is_owner = session.get('user_id') == owner_id
    return render_template("user_page.html", nodes=nodes_vis, edges=edges_vis, slug=slug, is_owner=is_owner)

@app.route('/edit/<slug>', methods=['GET', 'POST'])
def edit_page(slug):
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("SELECT id, name, email, photo_url FROM users WHERE slug = %s", (slug,))
            user = c.fetchone()
            if not user:
                return "Kullanıcı bulunamadı", 404
            owner_id = user['id']
            owner_name = user['name']
            if session.get("user_id") != owner_id:
                return "Yetkisiz giriş", 403

            if request.method == 'POST':
                validate_csrf()
                conn_id = request.form.get("delete_id")
                if conn_id:
                    c.execute("DELETE FROM connections WHERE id = %s AND owner_id = %s", (conn_id, owner_id))
                    conn.commit()

            c.execute("""
                SELECT id, visitor_name, connection_type, connector_name 
                FROM connections 
                WHERE owner_id = %s
                ORDER BY id DESC
            """, (owner_id,))
            connections = c.fetchall()

            c.execute("SELECT visitor_name, connection_type, connector_name FROM connections WHERE owner_id = %s", (owner_id,))
            rows = c.fetchall()

    nodes_vis, edges_vis = build_graph_multi(rows, [{"id": owner_id, "name": owner_name, "slug": slug}])
    return render_template(
        "edit.html",
        slug=slug, name=owner_name, connections=connections,
        nodes=nodes_vis, edges=edges_vis,
        user_profile={"email": user.get("email"), "photo_url": user.get("photo_url")}
    )

###############################################################################
# Başlat
###############################################################################
init_db()

if __name__ == '__main__':
    app.run(debug=True)

