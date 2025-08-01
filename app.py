from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os
from collections import defaultdict
import colorsys
import random

app = Flask(__name__)
app.secret_key = 'super-secret-key'
DB_FILE = 'data.db'

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                slug TEXT UNIQUE,
                password TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER,
                visitor_name TEXT,
                connection_type TEXT,
                connector_name TEXT
            )
        ''')
        conn.commit()

def random_color():
    h = random.random()
    s = 0.5 + random.random() * 0.5
    v = 0.7 + random.random() * 0.3
    r, g, b = colorsys.hsv_to_rgb(h, s, v)
    return f'rgb({int(r*255)}, {int(g*255)}, {int(b*255)})'

def mix_colors(colors):
    if not colors:
        return "#cccccc"
    r, g, b = 0, 0, 0
    for col in colors:
        if col.startswith("rgb"):
            vals = col[4:-1].split(',')
            r += int(vals[0])
            g += int(vals[1])
            b += int(vals[2])
    n = len(colors)
    return f"rgb({r//n}, {g//n}, {b//n})"

def build_graph_multi(rows, user_rows):
    owner_to_rows = defaultdict(list)
    for owner_id, visitor, ctype, connector in rows:
        owner_to_rows[owner_id].append((visitor, ctype, connector))

    user_id_to_name = {}
    user_name_to_slug = {}
    user_id_to_color = {}

    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT id, name, slug FROM users")
        for uid, name, slug in c.fetchall():
            user_id_to_name[uid] = name
            user_name_to_slug[name] = slug
            user_id_to_color[uid] = random_color()

    name_to_owners = defaultdict(set)
    all_edges = set()

    for owner_id, conns in owner_to_rows.items():
        owner_name = user_id_to_name[owner_id]
        name_to_connector = {}
        for visitor, ctype, connector in conns:
            name_to_connector[visitor] = (ctype, connector)
        for visitor in name_to_connector:
            person = visitor
            chain = []
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
            for frm, to in chain:
                all_edges.add((frm, to))
            for node in [visitor, *(c for _, c in chain), owner_name]:
                name_to_owners[node].add(owner_id)

    all_nodes = set()
    for frm, to in all_edges:
        all_nodes.add(frm)
        all_nodes.add(to)

    name_to_id = {name: i + 1 for i, name in enumerate(sorted(all_nodes))}
    nodes_vis = []
    for name, nid in name_to_id.items():
        owners = name_to_owners.get(name, set())
        colors = [user_id_to_color[o] for o in owners if o in user_id_to_color]
        if len(colors) == 1:
            color = colors[0]
        elif len(colors) > 1:
            color = mix_colors(colors)
        else:
            color = "#dddddd"
        node = {"id": nid, "label": name, "color": color}
        if name in user_name_to_slug:
            node["slug"] = user_name_to_slug[name]
        nodes_vis.append(node)

    edges_vis = [{"from": name_to_id[frm], "to": name_to_id[to]} for frm, to in all_edges]
    return nodes_vis, edges_vis

@app.route('/')
def index():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT owner_id, visitor_name, connection_type, connector_name FROM connections")
        conn_rows = c.fetchall()
        c.execute("SELECT name, slug FROM users")
        user_rows = c.fetchall()

        nodes, edges = build_graph_multi(conn_rows, user_rows)
        return render_template("global_graph.html", nodes=nodes, edges=edges)

@app.route('/create', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        name = request.form['name']
        slug = name.lower().replace(' ', '-')
        password = generate_password_hash(request.form['password'])
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            try:
                c.execute("INSERT INTO users (name, slug, password) VALUES (?, ?, ?)", (name, slug, password))
                conn.commit()
            except sqlite3.IntegrityError:
                return "Bu isim veya slug zaten alınmış."
        return redirect(url_for('login', slug=slug))
    return render_template("create.html")

@app.route('/login/<slug>', methods=['GET', 'POST'])
def login(slug):
    if request.method == 'POST':
        password = request.form['password']
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT id, password FROM users WHERE slug = ?", (slug,))
            row = c.fetchone()
            if row and check_password_hash(row[1], password):
                session['user_id'] = row[0]
                return redirect(url_for('edit_page', slug=slug))
        return "Şifre hatalı."
    return render_template("login.html", slug=slug)

@app.route('/<slug>', methods=['GET', 'POST'])
def user_page(slug):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT id, name FROM users WHERE slug = ?", (slug,))
        user = c.fetchone()
        if not user:
            return "Kullanıcı bulunamadı"
        owner_id, owner_name = user

        if request.method == 'POST' and session.get('user_id') != owner_id:
            visitor_name = request.form['name']
            connection_type = request.form['type']
            connector_name = request.form.get('connector')
            c.execute("SELECT visitor_name FROM connections WHERE owner_id = ? AND visitor_name = ?", (owner_id, visitor_name))
            if c.fetchone():
                return f"{visitor_name} zaten eklenmiş. Bu isim var. Hangi {visitor_name}?"
            c.execute("INSERT INTO connections (owner_id, visitor_name, connection_type, connector_name) VALUES (?, ?, ?, ?)",
                      (owner_id, visitor_name, connection_type, connector_name))
            conn.commit()
            return redirect(url_for('user_page', slug=slug))

        c.execute("SELECT visitor_name, connection_type, connector_name FROM connections WHERE owner_id = ?", (owner_id,))
        rows = c.fetchall()

    name_to_connector = {}
    for visitor, ctype, connector in rows:
        name_to_connector[visitor] = (ctype, connector)

    edges = []
    visited = set()
    for visitor in name_to_connector:
        person = visitor
        chain = []
        while True:
            ctype, connector = name_to_connector.get(person, (None, None))
            if connector:
                chain.append((person, connector))
                person = connector
            else:
                break
        if chain:
            last_node = chain[-1][1]
            edges.append((last_node, owner_name))
        else:
            edges.append((visitor, owner_name))
        edges += chain

    nodes = set()
    for frm, to in edges:
        nodes.add(frm)
        nodes.add(to)
    nodes.add(owner_name)

    name_to_id = {name: i + 1 for i, name in enumerate(sorted(nodes))}
    nodes_vis = []
    for name, nid in name_to_id.items():
        node = {"id": nid, "label": name}
        if name == owner_name:
            node["color"] = "lightgreen"
        nodes_vis.append(node)

    edges_vis = [{"from": name_to_id[frm], "to": name_to_id[to]} for frm, to in edges]
    is_owner = session.get('user_id') == owner_id
    return render_template("user_page.html", nodes=nodes_vis, edges=edges_vis, slug=slug, is_owner=is_owner)

@app.route('/edit/<slug>', methods=['GET', 'POST'])
def edit_page(slug):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE slug = ?", (slug,))
        user = c.fetchone()
        if not user:
            return "Kullanıcı bulunamadı"
        owner_id = user[0]
        if session.get("user_id") != owner_id:
            return "Yetkisiz giriş"

        if request.method == 'POST':
            conn_id = request.form.get("delete_id")
            c.execute("DELETE FROM connections WHERE id = ?", (conn_id,))
            conn.commit()

        c.execute("SELECT id, visitor_name, connection_type, connector_name FROM connections WHERE owner_id = ?", (owner_id,))
        connections = c.fetchall()

    return render_template("edit.html", slug=slug, connections=connections)
    
init_db()

if __name__ == '__main__':
    
    app.run(debug=True)
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

