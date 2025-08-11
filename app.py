# app.py  — TAM SÜRÜM (bakım modu eklendi)

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import os, random, colorsys, re, secrets, time
import psycopg2
from psycopg2.extras import RealDictCursor
from collections import defaultdict

###############################################################################
# Yardımcı: ortam değişkeni
###############################################################################

def env(key, default=None):
    v = os.environ.get(key)
    return v if v not in (None, "") else default

###############################################################################
# Uygulama ve Güvenlik Ayarları
###############################################################################

app = Flask(__name__)

# Secret key (prod için ortamdan)
app.secret_key = env("FLASK_SECRET_KEY", "super-secret-key")

# Session cookie güvenliği
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
if env("SESSION_COOKIE_SECURE", "0") == "1":
    app.config["SESSION_COOKIE_SECURE"] = True

###############################################################################
# Bakım Modu Ayarları
###############################################################################
# MAINTENANCE_MODE=1  -> tüm sayfalarda maintenance.html döner
# MAINTENANCE_ALLOW_IPS="1.2.3.4,5.6.7.8" -> bu IP'ler baypas eder
# MAINTENANCE_BYPASS_TOKEN="uzun-bir-gizli-token" -> /__maintenance-bypass?token=... ile baypas cookie’si
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
# Yardımcılar (slug, normalize, renk, DB vs.)
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

def get_db_connection():
    return psycopg2.connect(
        dbname=env("PGDATABASE", "railway"),
        user=env("PGUSER", "postgres"),
        password=env("PGPASSWORD", "BuYuHoBHNkQNGxbQHDGNCVrYtnLWhIvo"),
        host=env("PGHOST", "hopper.proxy.rlwy.net"),
        port=env("PGPORT", "36466"),
        cursor_factory=RealDictCursor
    )

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
    return f"rgb({avg_r}, {avg_g}, {avg_b})"

def fixed_color(user_id):
    palette = [
        "#4CAF50", "#81C784", "#66BB6A", "#388E3C", "#2E7D32",
        "#1B5E20", "#A5D6A7", "#43A047", "#00796B", "#33691E"
    ]
    return palette[user_id % len(palette)]

def build_graph_multi(rows, user_rows):
    from collections import defaultdict
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
# CSRF: Basit token
###############################################################################

def ensure_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(16)

def validate_csrf():
    form_token = request.form.get("csrf_token")
    if not form_token or form_token != session.get("csrf_token"):
        abort(400, description="Geçersiz CSRF token")

###############################################################################
# DB Şeması Kurulum / Göç
###############################################################################

def init_db():
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    name TEXT UNIQUE,
                    slug TEXT UNIQUE,
                    password TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS connections (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    visitor_name TEXT,
                    connection_type TEXT,
                    connector_name TEXT
                )
            """)
            c.execute("ALTER TABLE connections ADD COLUMN IF NOT EXISTS visitor_id INTEGER REFERENCES users(id)")
            c.execute("ALTER TABLE connections ADD COLUMN IF NOT EXISTS connector_id INTEGER REFERENCES users(id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_users_slug ON users(slug)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_connections_owner ON connections(owner_id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_connections_visitor_name ON connections(visitor_name)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_connections_connector_name ON connections(connector_name)")
        conn.commit()

###############################################################################
# Global Hook: Bakım Modu Kontrolü
###############################################################################

@app.before_request
def _pre():
    ensure_csrf_token()

    # Sağlık ve baypas endpoint'leri, statikler ve favicon her zaman açık
    open_paths = (
        "/healthz",
        "/__maintenance-bypass",
        "/maintenance",         # doğrudan sayfa test etmek için
        "/favicon.ico",
        "/robots.txt",
    )
    if request.path.startswith("/static/") or request.path in open_paths:
        return

    if maintenance_active():
        # izinli IP ya da baypas cookie varsa geç
        if maintenance_allowed_ip(request.remote_addr) or maintenance_bypass_ok():
            return
        # aksi halde maintenance sayfasını 503 ile döndür
        resp = make_response(render_template("maintenance.html"), 503)
        resp.headers["Retry-After"] = "3600"  # 1 saat sonra tekrar dene
        return resp

###############################################################################
# Bakım Baypas Yardımcıları
###############################################################################

@app.get("/__maintenance-bypass")
def maintenance_bypass():
    """ Gizli token doğrulanırsa baypas cookie'si set edilir. 
        Kullanım: /__maintenance-bypass?token=SECRETTOKEN
    """
    token = env("MAINTENANCE_BYPASS_TOKEN", "")
    given = request.args.get("token", "")
    if not token:
        return "BYPASS devre dışı (MAINTENANCE_BYPASS_TOKEN ayarlanmadı).", 400
    if given != token:
        return "Geçersiz token.", 403
    resp = make_response("Baypas aktif. Çerez set edildi.")
    resp.set_cookie(MAINTENANCE_COOKIE, token, httponly=True, samesite="Lax", secure=app.config.get("SESSION_COOKIE_SECURE", False), max_age=60*60*3)
    return resp

@app.get("/maintenance")
def maintenance_page_direct():
    """ Bakım sayfasını doğrudan görmek için. """
    return render_template("maintenance.html"), 503

@app.get("/healthz")
def healthz():
    return "ok", 200

###############################################################################
# Rotalar (mevcut uygulama)
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

@app.route('/suggest')
def suggest():
    query = request.args.get('q', '').lower()
    if not query or len(query) < 2:
        return jsonify(results=[])
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("SELECT name, slug FROM users WHERE LOWER(name) LIKE %s ORDER BY name LIMIT 10", (f"%{query}%",))
            users = c.fetchall()
    return jsonify(results=users)

@app.route('/create', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        validate_csrf()
        name = request.form['name'].strip()
        if len(name) < 2:
            return "İsim çok kısa.", 400
        slug = slugify(name)
        password = generate_password_hash(request.form['password'])
        with get_db_connection() as conn:
            with conn.cursor() as c:
                try:
                    c.execute("INSERT INTO users (name, slug, password) VALUES (%s, %s, %s)", (name, slug, password))
                    conn.commit()
                except psycopg2.Error as e:
                    conn.rollback()
                    if getattr(e, "pgcode", "") == "23505":
                        return "Bu isim veya slug zaten alınmış.", 409
                    return "Kayıt sırasında hata oluştu.", 500
        return redirect(url_for('login', slug=slug))
    return render_template("create.html", csrf_token=session["csrf_token"])

@app.route('/login', methods=['GET', 'POST'])
@app.route('/login/<slug>', methods=['GET', 'POST'])
def login(slug=None):
    if request.method == 'POST':
        validate_csrf()
        name = request.form['name']
        password = request.form['password']
        eff_slug = slugify(name) if not slug else slug
        with get_db_connection() as conn:
            with conn.cursor() as c:
                c.execute("SELECT id, password FROM users WHERE slug = %s", (eff_slug,))
                user = c.fetchone()
                if user and check_password_hash(user['password'], password):
                    session['user_id'] = user['id']
                    return redirect(url_for('edit_page', slug=eff_slug))
                else:
                    return "İsim veya şifre hatalı.", 401
    return render_template("login.html", csrf_token=session["csrf_token"])

@app.route('/logout')
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
            c.execute("SELECT id, name FROM users WHERE slug = %s", (slug,))
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
    return render_template("edit.html", slug=slug, name=owner_name, connections=connections, nodes=nodes_vis, edges=edges_vis)

###############################################################################
# Yönetim / Yardımcı Rotalar
###############################################################################

@app.route('/merge-connectors')
def merge_connectors():
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("""
                UPDATE connections
                SET connector_id = users.id
                FROM users
                WHERE connections.connector_name = users.name
            """)
            conn.commit()
    return "connector_id alanları users ile eşleştirildi."

@app.route('/fix-visitor-ids')
def fix_visitor_ids():
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("""
                UPDATE connections
                SET visitor_id = users.id
                FROM users
                WHERE connections.visitor_name = users.name
            """)
            conn.commit()
    return "visitor_id alanları users ile eşleştirildi!"

###############################################################################
# Uygulama Başlatma
###############################################################################

init_db()

if __name__ == '__main__':
    app.run(debug=True)

