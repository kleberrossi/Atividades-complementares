# coding: utf-8
import os
import sqlite3
import json
import datetime
import hashlib  # Substituindo bcrypt por hashlib
import base64   # Para codificação/decodificação de salt
import secrets  # Para geração segura de salt
import openpyxl
import logging
import traceback
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify, g
from werkzeug.utils import secure_filename

try:
    from unidecode import unidecode
except ImportError:
    # Fallback se unidecode não estiver disponível
    def unidecode(text):
        return text

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or session["user_type"] != "admin":
            flash("Acesso não autorizado.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# Função auxiliar para normalizar cabeçalhos/nomes
def normalize_header(text):
    if not isinstance(text, str):
        text = str(text)
    text = unidecode(text)
    return " ".join(text.lower().split())

# Funções para substituir bcrypt com hashlib puro Python
def hash_password(password):
    """Cria um hash seguro para a senha usando hashlib (SHA-256) com salt"""
    # Gerar um salt aleatório
    salt = secrets.token_bytes(16)
    # Criar hash com salt
    h = hashlib.sha256()
    h.update(salt + password.encode("utf-8"))
    password_hash = h.digest()
    # Retornar salt e hash codificados em base64 para armazenamento
    return base64.b64encode(salt).decode("utf-8") + "$" + base64.b64encode(password_hash).decode("utf-8")

def check_password(stored_password, provided_password):
    """Verifica se a senha fornecida corresponde ao hash armazenado"""
    try:
        # Separar salt e hash
        salt_b64, hash_b64 = stored_password.split("$")
        # Decodificar salt
        salt = base64.b64decode(salt_b64)
        # Recriar hash com a senha fornecida
        h = hashlib.sha256()
        h.update(salt + provided_password.encode("utf-8"))
        calculated_hash = h.digest()
        # Comparar com o hash armazenado
        stored_hash = base64.b64decode(hash_b64)
        return secrets.compare_digest(calculated_hash, stored_hash)
    except Exception as e:
        logging.error(f"Erro ao verificar senha: {e}")
        return False

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = "ej_atividades_complementares_2025"
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

DATABASE = "database.db"

def get_db_connection():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    try:
        conn = get_db_connection()
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
        CREATE TABLE IF NOT EXISTS alunos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER UNIQUE,
            nome TEXT NOT NULL,
            matricula TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            turma TEXT,
            status TEXT DEFAULT 'Ativo' CHECK(status IN ('Ativo', 'Inativo')),
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS atividades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            grupo TEXT NOT NULL,
            nome TEXT NOT NULL UNIQUE,
            limite_horas INTEGER,
            tipo_atividade TEXT NOT NULL DEFAULT 'Acadêmica Complementar' CHECK(tipo_atividade IN ('Acadêmica Complementar', 'Extensão Universitária')),
            tem_limitacao BOOLEAN DEFAULT 0,
            tipo_limitacao TEXT CHECK(tipo_limitacao IN ('total', 'semestral')),
            limite_horas_total INTEGER,
            limite_horas_semestral INTEGER
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS requisicoes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            aluno_id INTEGER,
            atividade_id INTEGER NOT NULL,
            data_solicitacao TEXT NOT NULL,
            data_evento TEXT NOT NULL,
            horas_solicitadas REAL NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('Pendente', 'Deferida', 'Deferida Parcialmente', 'Indeferida')),
            horas_deferidas REAL,
            observacao TEXT,
            arquivo_comprovante TEXT,
            data_processamento TEXT,
            admin_id INTEGER,
            FOREIGN KEY (aluno_id) REFERENCES usuarios (id),
            FOREIGN KEY (atividade_id) REFERENCES atividades (id),
            FOREIGN KEY (admin_id) REFERENCES usuarios (id)
        );
        """)
        
        admin_exists = conn.execute("SELECT 1 FROM usuarios WHERE email = ?", ("admin@ej.edu.br",)).fetchone()
        if not admin_exists:
            # Usar novo método de hash para a senha do admin
            hashed_password = hash_password("admin123")
            conn.execute("INSERT INTO usuarios (nome, email, senha, tipo) VALUES (?, ?, ?, ?)",
                         ("Administrador", "admin@ej.edu.br", hashed_password, "admin"))
        
        # Migração: Adicionar coluna tipo_atividade se não existir
        try:
            conn.execute("ALTER TABLE atividades ADD COLUMN tipo_atividade TEXT NOT NULL DEFAULT 'Acadêmica Complementar' CHECK(tipo_atividade IN ('Acadêmica Complementar', 'Extensão Universitária'))")
        except sqlite3.OperationalError:
            # Coluna já existe, ignorar erro
            pass
        
        # Migração: Adicionar colunas de limitação se não existirem
        try:
            conn.execute("ALTER TABLE atividades ADD COLUMN tem_limitacao BOOLEAN DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        
        try:
            conn.execute("ALTER TABLE atividades ADD COLUMN tipo_limitacao TEXT CHECK(tipo_limitacao IN ('total', 'semestral'))")
        except sqlite3.OperationalError:
            pass
        
        try:
            conn.execute("ALTER TABLE atividades ADD COLUMN limite_horas_total INTEGER")
        except sqlite3.OperationalError:
            pass
        
        try:
            conn.execute("ALTER TABLE atividades ADD COLUMN limite_horas_semestral INTEGER")
        except sqlite3.OperationalError:
            pass
        
        # Atualizar atividades existentes que não têm tipo definido
        conn.execute("UPDATE atividades SET tipo_atividade = 'Acadêmica Complementar' WHERE tipo_atividade IS NULL OR tipo_atividade = ''")
        
        conn.commit()
        logger.info("Banco de dados inicializado com sucesso")
    except Exception as e:
        logger.error(f"Erro ao inicializar banco de dados: {e}")
        raise

# --- Rotas de Autenticação ---

@app.route("/login", methods=["GET", "POST"])
def login():
    try:
        if request.method == "POST":
            email = request.form["email"]
            senha = request.form["senha"]
            conn = get_db_connection()
            user = conn.execute("SELECT * FROM usuarios WHERE email = ?", (email,)).fetchone()

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
    except Exception as e:
        logger.error(f"Erro no login: {e}")
        flash("Erro interno do servidor. Tente novamente.", "error")
        return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("user_type", None)
    session.pop("user_name", None)
    flash("Você foi desconectado.", "info")
    return redirect(url_for("login"))

@app.route("/")
def index():
    return redirect(url_for("login"))

# --- Rotas Admin --- 

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    try:
        conn = get_db_connection()
        total_alunos = conn.execute("SELECT COUNT(*) FROM alunos").fetchone()[0]
        
        # Estatísticas por tipo de atividade
        total_atividades_academicas = conn.execute("SELECT COUNT(*) FROM atividades WHERE tipo_atividade = 'Acadêmica Complementar'").fetchone()[0]
        total_atividades_extensao = conn.execute("SELECT COUNT(*) FROM atividades WHERE tipo_atividade = 'Extensão Universitária'").fetchone()[0]
        total_atividades = total_atividades_academicas + total_atividades_extensao
        
        # Estatísticas de requisições
        total_requisicoes = conn.execute("SELECT COUNT(*) FROM requisicoes").fetchone()[0]
        requisicoes_pendentes = conn.execute("SELECT COUNT(*) FROM requisicoes WHERE status = 'Pendente'").fetchone()[0]
        
        # Requisições por tipo de atividade
        requisicoes_academicas = conn.execute("""
            SELECT COUNT(*) FROM requisicoes r 
            JOIN atividades a ON r.atividade_id = a.id 
            WHERE a.tipo_atividade = 'Acadêmica Complementar'
        """).fetchone()[0]
        
        requisicoes_extensao = conn.execute("""
            SELECT COUNT(*) FROM requisicoes r 
            JOIN atividades a ON r.atividade_id = a.id 
            WHERE a.tipo_atividade = 'Extensão Universitária'
        """).fetchone()[0]
        
        return render_template("admin_dashboard.html", 
                               total_alunos=total_alunos, 
                               total_atividades=total_atividades,
                               total_atividades_academicas=total_atividades_academicas,
                               total_atividades_extensao=total_atividades_extensao,
                               total_requisicoes=total_requisicoes,
                               requisicoes_pendentes=requisicoes_pendentes,
                               requisicoes_academicas=requisicoes_academicas,
                               requisicoes_extensao=requisicoes_extensao)
    except Exception as e:
        logger.error(f"Erro no dashboard admin: {e}")
        flash("Erro ao carregar dashboard.", "error")
        return redirect(url_for("login"))

@app.route("/admin/adicionar_atividade", methods=["GET", "POST"])
@admin_required
def admin_adicionar_atividade():
    try:
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
        return render_template("admin_adicionar_atividade.html")
    except Exception as e:
        logger.error(f"Erro ao adicionar atividade: {e}")
        flash("Erro interno do servidor.", "error")
        return render_template("admin_adicionar_atividade.html")

@app.route("/admin/atividades")
@admin_required
def admin_atividades():
    try:
        conn = get_db_connection()
        atividades = conn.execute("SELECT * FROM atividades ORDER BY tipo_atividade, grupo, nome").fetchall()
        return render_template("admin_atividades.html", atividades=atividades)
    except Exception as e:
        logger.error(f"Erro ao listar atividades: {e}")
        flash("Erro ao carregar atividades.", "error")
        return redirect(url_for("admin_dashboard"))

@app.route("/admin/atividades/academicas")
@admin_required
def admin_atividades_academicas():
    try:
        conn = get_db_connection()
        atividades = conn.execute("SELECT * FROM atividades WHERE tipo_atividade = 'Acadêmica Complementar' ORDER BY grupo, nome").fetchall()
        return render_template("admin_atividades_academicas.html", atividades=atividades)
    except Exception as e:
        logger.error(f"Erro ao listar atividades acadêmicas: {e}")
        flash("Erro ao carregar atividades acadêmicas.", "error")
        return redirect(url_for("admin_dashboard"))

@app.route("/admin/atividades/extensao")
@admin_required
def admin_atividades_extensao():
    try:
        conn = get_db_connection()
        atividades = conn.execute("SELECT * FROM atividades WHERE tipo_atividade = 'Extensão Universitária' ORDER BY grupo, nome").fetchall()
        return render_template("admin_atividades_extensao.html", atividades=atividades)
    except Exception as e:
        logger.error(f"Erro ao listar atividades de extensão: {e}")
        flash("Erro ao carregar atividades de extensão.", "error")
        return redirect(url_for("admin_dashboard"))

if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=False, host="0.0.0.0", port=5000)

