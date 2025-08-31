import os
import sqlite3
import hashlib
import base64
import secrets
import logging
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or session["user_type"] != "admin":
            flash("Acesso não autorizado.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def hash_password(password):
    salt = secrets.token_bytes(16)
    h = hashlib.sha256()
    h.update(salt + password.encode("utf-8"))
    password_hash = h.digest()
    return base64.b64encode(salt).decode("utf-8") + "$" + base64.b64encode(password_hash).decode("utf-8")

def check_password(stored_password, provided_password):
    try:
        salt_b64, hash_b64 = stored_password.split("$")
        salt = base64.b64decode(salt_b64)
        h = hashlib.sha256()
        h.update(salt + provided_password.encode("utf-8"))
        calculated_hash = h.digest()
        stored_hash = base64.b64decode(hash_b64)
        return secrets.compare_digest(calculated_hash, stored_hash)
    except:
        return False

app = Flask(__name__)
app.secret_key = "ej_atividades_complementares_2025"

DATABASE = "database.db"

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    
    # Criar tabelas
    conn.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        senha TEXT NOT NULL,
        tipo TEXT NOT NULL CHECK(tipo IN ("admin", "aluno"))
    );
    """)
    
    conn.execute("""
    CREATE TABLE IF NOT EXISTS atividades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        grupo TEXT NOT NULL,
        nome TEXT NOT NULL UNIQUE,
        limite_horas INTEGER,
        tipo_atividade TEXT NOT NULL DEFAULT 'Acadêmica Complementar',
        tem_limitacao BOOLEAN DEFAULT 0,
        tipo_limitacao TEXT,
        limite_horas_total INTEGER,
        limite_horas_semestral INTEGER
    );
    """)
    
    # Criar admin se não existir
    admin_exists = conn.execute("SELECT 1 FROM usuarios WHERE email = ?", ("admin@ej.edu.br",)).fetchone()
    if not admin_exists:
        hashed_password = hash_password("admin123")
        conn.execute("INSERT INTO usuarios (nome, email, senha, tipo) VALUES (?, ?, ?, ?)",
                     ("Administrador", "admin@ej.edu.br", hashed_password, "admin"))
    
    conn.commit()
    conn.close()

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        senha = request.form["senha"]
        
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM usuarios WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user and check_password(user["senha"], senha):
            session["user_id"] = user["id"]
            session["user_type"] = user["tipo"]
            session["user_name"] = user["nome"]
            flash("Login realizado com sucesso!", "success")
            if user["tipo"] == "admin":
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("aluno_dashboard"))
        else:
            flash("E-mail ou senha inválidos.", "error")
    
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Você foi desconectado.", "info")
    return redirect(url_for("login"))

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    
    # Estatísticas básicas
    total_alunos = 0
    total_atividades_academicas = conn.execute("SELECT COUNT(*) FROM atividades WHERE tipo_atividade = 'Acadêmica Complementar'").fetchone()[0]
    total_atividades_extensao = conn.execute("SELECT COUNT(*) FROM atividades WHERE tipo_atividade = 'Extensão Universitária'").fetchone()[0]
    total_atividades = total_atividades_academicas + total_atividades_extensao
    total_requisicoes = 0
    requisicoes_pendentes = 0
    requisicoes_academicas = 0
    requisicoes_extensao = 0
    
    conn.close()
    
    return render_template("admin_dashboard.html", 
                           total_alunos=total_alunos, 
                           total_atividades=total_atividades,
                           total_atividades_academicas=total_atividades_academicas,
                           total_atividades_extensao=total_atividades_extensao,
                           total_requisicoes=total_requisicoes,
                           requisicoes_pendentes=requisicoes_pendentes,
                           requisicoes_academicas=requisicoes_academicas,
                           requisicoes_extensao=requisicoes_extensao)

@app.route("/admin/atividades")
@admin_required
def admin_atividades():
    conn = get_db_connection()
    atividades = conn.execute("SELECT * FROM atividades ORDER BY tipo_atividade, grupo, nome").fetchall()
    conn.close()
    return render_template("admin_atividades.html", atividades=atividades)

@app.route("/admin/atividades/academicas")
@admin_required
def admin_atividades_academicas():
    conn = get_db_connection()
    atividades = conn.execute("SELECT * FROM atividades WHERE tipo_atividade = 'Acadêmica Complementar' ORDER BY grupo, nome").fetchall()
    conn.close()
    return render_template("admin_atividades_academicas.html", atividades=atividades)

@app.route("/admin/atividades/extensao")
@admin_required
def admin_atividades_extensao():
    conn = get_db_connection()
    atividades = conn.execute("SELECT * FROM atividades WHERE tipo_atividade = 'Extensão Universitária' ORDER BY grupo, nome").fetchall()
    conn.close()
    return render_template("admin_atividades_extensao.html", atividades=atividades)

@app.route("/admin/adicionar_atividade", methods=["GET", "POST"])
@admin_required
def admin_adicionar_atividade():
    if request.method == "POST":
        grupo = request.form["grupo"]
        nome = request.form["nome"]
        limite_horas = request.form.get("limite_horas")
        tipo_atividade = request.form["tipo_atividade"]
        
        # Campos de limitação
        tem_limitacao = 'tem_limitacao' in request.form
        tipo_limitacao = request.form.get("tipo_limitacao") if tem_limitacao else None
        limite_horas_total = request.form.get("limite_horas_total") if tem_limitacao and tipo_limitacao == "total" else None
        limite_horas_semestral = request.form.get("limite_horas_semestral") if tem_limitacao and tipo_limitacao == "semestral" else None
        
        # Converter valores vazios para None
        if limite_horas == "":
            limite_horas = None
        if limite_horas_total == "":
            limite_horas_total = None
        if limite_horas_semestral == "":
            limite_horas_semestral = None

        conn = get_db_connection()
        try:
            conn.execute("""
                INSERT INTO atividades 
                (grupo, nome, limite_horas, tipo_atividade, tem_limitacao, tipo_limitacao, limite_horas_total, limite_horas_semestral) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (grupo, nome, limite_horas, tipo_atividade, tem_limitacao, tipo_limitacao, limite_horas_total, limite_horas_semestral))
            conn.commit()
            flash("Atividade adicionada com sucesso.", "success")
            return redirect(url_for("admin_atividades"))
        except sqlite3.IntegrityError:
            flash("Erro: Atividade com este nome já existe.", "error")
        finally:
            conn.close()
    
    return render_template("admin_adicionar_atividade.html")

@app.route("/aluno/dashboard")
def aluno_dashboard():
    if "user_id" not in session or session["user_type"] != "aluno":
        flash("Acesso não autorizado.", "error")
        return redirect(url_for("login"))
    
    # Dados básicos para o dashboard do aluno
    horas_academicas = 0
    horas_extensao = 0
    total_horas = 0
    
    return render_template("aluno_dashboard.html",
                           horas_academicas=horas_academicas,
                           horas_extensao=horas_extensao,
                           total_horas=total_horas,
                           horas_por_tipo={},
                           horas_por_grupo={},
                           limites_por_grupo={},
                           total_horas_academicas=horas_academicas,
                           total_horas_extensao=horas_extensao)

if __name__ == "__main__":
    init_db()
    app.run(debug=False, host="0.0.0.0", port=5000)

