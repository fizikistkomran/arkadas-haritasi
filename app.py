from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import os, random, colorsys, re
import psycopg2
from psycopg2.extras import RealDictCursor
from collections import defaultdict

app = Flask(__name__)
app.secret_key = 'super-secret-key'

# Slugify fonksiyonu
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

# Veritabanı bağlantısı
def get_db_connection():
    return psycopg2.connect(
        dbname="railway",
        user="postgres",
        password="BuYuHoBHNkQNGxbQHDGNCVrYtnLWhIvo",
        host="hopper.proxy.rlwy.net",
        port="36466",
        cursor_factory=RealDictCursor
    )

# Tabloları oluştur
def init_db():
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    name TEXT UNIQUE,
                    slug TEXT UNIQUE,
                    password TEXT
                )
            ''')
            c.execute('''
                CREATE TABLE IF NOT EXISTS connections (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER,
                    visitor_name TEXT,
                    connection_type TEXT,
                    connector_name TEXT
                )
            ''')
        conn.commit()

# Renkler
def random_color():
    h, s, v = random.random(), 0.5 + random.random() * 0.5, 0.7 + random.random() * 0.3
    r, g, b = colorsys.hsv_to_rgb(h, s, v)
    return f'rgb({int(r*255)}, {int(g*255)}, {int(b*255)})'

def mix_colors(colors):
    if not colors: return "#cccccc"
    r = sum(int(col[4:-1].split(',')[0]) for col in colors)
    g = sum(int(col[4:-1].split(',')[1]) for col in colors)
    b = sum(int(col[4:-1].split(',')[2]) for col in colors)
    n = len(colors)
    return f"rgb({r//n}, {g//n}, {b//n})"

# Grafiği oluştur
def build_graph_multi(rows, user_rows):
    owner_to_rows = defaultdict(list)
    for row in rows:
        if 'owner_id' in row:
            owner_to_rows[row['owner_id']].append((row['visitor_name'], row['connection_type'], row['connector_name']))

    user_id_to_name = {u['id']: u['name'] for u in user_rows}
    user_name_to_slug = {u['name']: u['slug'] for u in user_rows}
    user_id_to_color = {u['id']: random_color() for u in user_rows}

    name_to_owners = defaultdict(set)
    all_edges = set()

    for owner_id, conns in owner_to_rows.items():
        owner_name = user_id_to_name.get(owner_id, f"user_{owner_id}")
        name_to_connector = {v: (t, c) for v, t, c in conns}
        for visitor in name_to_connector:
            person, chain = visitor, []
            while True:
                ctype, connector = name_to_connector.get(person, (None, None))
                if connector:
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
    if not query:
        return jsonify(results=[])
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("SELECT name, slug FROM users WHERE LOWER(name) LIKE %s LIMIT 10", (f"%{query}%",))
            users = c.fetchall()
    return jsonify(results=users)

@app.route('/login', methods=['GET', 'POST'])
def login_redirect():
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        slug = slugify(name)
        with get_db_connection() as conn:
            with conn.cursor() as c:
                c.execute("SELECT id, password FROM users WHERE slug = %s", (slug,))
                row = c.fetchone()
                if row and check_password_hash(row['password'], password):
                    session['user_id'] = row['id']
                    return redirect(url_for('edit_page', slug=slug))
        return "İsim veya şifre hatalı."
    return render_template("login.html")

@app.route('/create', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        name = request.form['name']
        slug = slugify(name)
        password = generate_password_hash(request.form['password'])
        with get_db_connection() as conn:
            with conn.cursor() as c:
                try:
                    c.execute("INSERT INTO users (name, slug, password) VALUES (%s, %s, %s)", (name, slug, password))
                    conn.commit()
                except psycopg2.errors.UniqueViolation:
                    conn.rollback()
                    return "Bu isim veya slug zaten alınmış."
        return redirect(url_for('login', slug=slug))
    return render_template("create.html")

@app.route('/edit/<slug>', methods=['GET', 'POST'])
def edit_page(slug):
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("SELECT id, name FROM users WHERE slug = %s", (slug,))
            user = c.fetchone()
            if not user:
                return "Kullanıcı bulunamadı"
            owner_id = user['id']
            owner_name = user['name']
            if session.get("user_id") != owner_id:
                return "Yetkisiz giriş"
            if request.method == 'POST':
                conn_id = request.form.get("delete_id")
                if conn_id:
                    c.execute("DELETE FROM connections WHERE id = %s", (conn_id,))
                    conn.commit()
            c.execute("""
                SELECT id, visitor_name, connection_type, connector_name 
                FROM connections 
                WHERE owner_id = %s
                ORDER BY id DESC
            """, (owner_id,))
            connections = c.fetchall()
    return render_template("edit.html", slug=slug, name=owner_name, connections=connections)

@app.route('/<slug>', methods=['GET', 'POST'])
def user_page(slug):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT id, name FROM users WHERE slug = ?", (slug,))
        user = c.fetchone()
        if not user:
            return "Kullanıcı bulunamadı"
        owner_id, owner_name = user

        if request.method == 'POST':
            if session.get('user_id') != owner_id:
                visitor_name = request.form['name']
                connection_type = request.form['type']
                connector_name = request.form.get('connector')

                # Aynı kişi tekrar eklenmiş mi kontrolü
                c.execute("SELECT 1 FROM connections WHERE owner_id = ? AND visitor_name = ?", (owner_id, visitor_name))
                if c.fetchone():
                    return f"{visitor_name} zaten eklenmiş."

                try:
                    c.execute(
                        "INSERT INTO connections (owner_id, visitor_name, connection_type, connector_name) VALUES (?, ?, ?, ?)",
                        (owner_id, visitor_name, connection_type, connector_name)
                    )
                    conn.commit()
                except Exception as e:
                    return f"Bağlantı eklenirken hata oluştu: {e}"

                return redirect(url_for('user_page', slug=slug))

        # Bağlantıları getir
        c.execute("SELECT visitor_name, connection_type, connector_name FROM connections WHERE owner_id = ?", (owner_id,))
        rows = c.fetchall()

    # Graph için bağlantıları çözümle
    name_to_connector = {}
    for visitor, ctype, connector in rows:
        if visitor not in name_to_connector:
            name_to_connector[visitor] = (ctype, connector)

    edges = []
    for visitor in name_to_connector:
        person = visitor
        chain = []
        while True:
            ctype, connector = name_to_connector.get(person, (None, None))
            if connector and connector != person:
                chain.append((person, connector))
                person = connector
            else:
                break
        if chain:
            edges.append((chain[-1][1], owner_name))
        else:
            edges.append((visitor, owner_name))
        edges.extend(chain)

    # Node'ları oluştur
    nodes = {owner_name}
    for f, t in edges:
        nodes.add(f)
        nodes.add(t)

    name_to_id = {name: i + 1 for i, name in enumerate(sorted(nodes))}
    nodes_vis = []
    for name, nid in name_to_id.items():
        node = {"id": nid, "label": name}
        if name == owner_name:
            node["color"] = "lightgreen"
        nodes_vis.append(node)

    edges_vis = [{"from": name_to_id[f], "to": name_to_id[t]} for f, t in edges]
    is_owner = session.get('user_id') == owner_id
    return render_template("user_page.html", nodes=nodes_vis, edges=edges_vis, slug=slug, is_owner=is_owner)

# Başlat
init_db()

if __name__ == '__main__':
    app.run()

