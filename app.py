import os
import sys
import uuid
import json
import atexit
import shutil
from datetime import datetime, timedelta
from functools import wraps

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'crypto'))

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

# ===== БАЗА ДАННЫХ =====
db = SQLAlchemy()

ROLES = ['admin', 'general_director', 'secretary', 'department_head', 'executor', 'approver', 'courier']

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(255))
    full_name = db.Column(db.String(150))
    role = db.Column(db.String(30))
    company_id = db.Column(db.Integer)
    public_key = db.Column(db.Text)
    private_key_encrypted = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_authenticated(self):
        return True
    
    def is_active(self):
        return self.is_active
    
    def is_anonymous(self):
        return False
    
    def get_id(self):
        return str(self.id)

class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    inn = db.Column(db.String(12))
    director_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    users = db.relationship('User', backref='company_ref', lazy=True)
    documents = db.relationship('Document', backref='company_ref', lazy=True)
    director = db.relationship('User', foreign_keys=[director_id])

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True)
    type = db.Column(db.String(50))
    title = db.Column(db.String(500))
    file_path = db.Column(db.String(500))
    original_hash = db.Column(db.String(64))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'))
    current_stage = db.Column(db.Integer, default=1)
    status = db.Column(db.String(20), default='draft')
    route_config = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    author = db.relationship('User', foreign_keys=[author_id])
    stages = db.relationship('DocumentStage', backref='document_ref', lazy=True)
    company = db.relationship('Company', foreign_keys=[company_id])

class DocumentStage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'))
    stage_number = db.Column(db.Integer)
    role_required = db.Column(db.String(50))
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(50))
    status = db.Column(db.String(20), default='pending')
    signature = db.Column(db.Text)
    encrypted_key = db.Column(db.Text)
    comments = db.Column(db.Text)
    completed_at = db.Column(db.DateTime)
    deadline = db.Column(db.Date)
    
    assigned_user = db.relationship('User', foreign_keys=[assigned_to])

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    ip_address = db.Column(db.String(45))
    action = db.Column(db.String(100))
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'))
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='audit_logs')

# ===== ПРОСТОЙ КРИПТОАДАПТЕР =====
class SimpleCrypto:
    def __init__(self):
        print("✓ Используется простой криптоадаптер")
    
    def generate_key_pair(self):
        private_key = "PRIVATE_KEY_" + str(uuid.uuid4())
        public_key = "PUBLIC_KEY_" + str(uuid.uuid4())
        return private_key, public_key
    
    def sign_document(self, file_path, private_key):
        return f"SIGNATURE_{os.path.basename(file_path)}_{datetime.now().timestamp()}"
    
    def verify_signature(self, file_path, signature, public_key):
        return True
    
    def encrypt_file(self, file_path, key):
        encrypted_path = file_path + '.enc'
        with open(file_path, 'rb') as f:
            content = f.read()
        with open(encrypted_path, 'wb') as f:
            f.write(content + b" [ENCRYPTED]")
        
        # Сохраняем метаданные
        metadata = {'key': 'demo_key', 'algorithm': 'simple'}
        with open(encrypted_path + '.meta', 'w') as f:
            json.dump(metadata, f)
        
        return encrypted_path
    
    def decrypt_file(self, file_path, key):
        if not file_path.endswith('.enc'):
            return file_path
        
        decrypted_path = file_path.replace('.enc', '_decrypted')
        with open(file_path, 'rb') as f:
            content = f.read()
        with open(decrypted_path, 'wb') as f:
            if content.endswith(b" [ENCRYPTED]"):
                f.write(content[:-12])
            else:
                f.write(content)
        
        return decrypted_path
    
    def calculate_hash(self, file_path):
        import hashlib
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return "0" * 64

crypto = SimpleCrypto()

# ===== ПУТИ ДОКУМЕНТОВ =====
DOCUMENT_ROUTES = {
    'service_note': [
        {'stage': 1, 'role': 'department_head', 'action': 'review', 'title': 'Согласование'},
        {'stage': 2, 'role': 'executor', 'action': 'encrypt', 'title': 'Шифрование'}
    ],
    'order': [
        {'stage': 1, 'role': 'secretary', 'action': 'register', 'title': 'Регистрация'},
        {'stage': 2, 'role': 'department_head', 'action': 'review', 'title': 'Согласование'},
        {'stage': 3, 'role': 'approver', 'action': 'approve', 'title': 'Утверждение'},
        {'stage': 4, 'role': 'executor', 'action': 'send', 'title': 'Отправка'}
    ],
    'cover_letter': [
        {'stage': 1, 'role': 'secretary', 'action': 'register', 'title': 'Регистрация'},
        {'stage': 2, 'role': 'department_head', 'action': 'review', 'title': 'Проверка'},
        {'stage': 3, 'role': 'approver', 'action': 'approve', 'title': 'Утверждение'},
        {'stage': 4, 'role': 'executor', 'action': 'encrypt', 'title': 'Шифрование'},
        {'stage': 5, 'role': 'courier', 'action': 'send', 'title': 'Отправка'}
    ]
}

# ===== ПРАВА =====
ROLE_PERMISSIONS = {
    'admin': {
        'can_view_all_companies': True,
        'can_manage_companies': True,
        'can_view_audit_log': True,
        'can_view_security_dashboard': True,
        'can_create_document': True,
        'can_sign_document': True,
        'can_encrypt_document': True,
        'can_approve_document': True,
        'can_review_document': True,
        'can_register_document': True,
        'can_send_document': True,
        'can_view_all_documents': True,
        'can_manage_users': True,
    },
    'general_director': {
        'can_view_all_companies': False,
        'can_manage_companies': False,
        'can_view_audit_log': True,
        'can_view_security_dashboard': True,
        'can_create_document': True,
        'can_sign_document': True,
        'can_encrypt_document': True,
        'can_approve_document': True,
        'can_review_document': True,
        'can_register_document': True,
        'can_send_document': True,
        'can_view_all_documents': True,
        'can_manage_users': True,
    },
    'secretary': {
        'can_create_document': True,
        'can_sign_document': False,
        'can_encrypt_document': False,
        'can_approve_document': False,
        'can_review_document': False,
        'can_register_document': True,
        'can_send_document': True,
        'can_view_all_documents': True,
        'can_manage_users': False,
    },
    'department_head': {
        'can_create_document': True,
        'can_sign_document': False,
        'can_encrypt_document': False,
        'can_approve_document': False,
        'can_review_document': True,
        'can_register_document': False,
        'can_send_document': False,
        'can_view_all_documents': True,
        'can_manage_users': False,
    },
    'executor': {
        'can_create_document': True,
        'can_sign_document': False,
        'can_encrypt_document': True,
        'can_approve_document': False,
        'can_review_document': False,
        'can_register_document': False,
        'can_send_document': True,
        'can_view_all_documents': True,
        'can_manage_users': False,
    },
    'approver': {
        'can_create_document': False,
        'can_sign_document': False,
        'can_encrypt_document': False,
        'can_approve_document': True,
        'can_review_document': False,
        'can_register_document': False,
        'can_send_document': False,
        'can_view_all_documents': True,
        'can_manage_users': False,
    },
    'courier': {
        'can_create_document': False,
        'can_sign_document': False,
        'can_encrypt_document': False,
        'can_approve_document': False,
        'can_review_document': False,
        'can_register_document': False,
        'can_send_document': True,
        'can_view_all_documents': True,
        'can_manage_users': False,
    }
}

# ===== ФУНКЦИИ =====
def has_permission(role, permission):
    return ROLE_PERMISSIONS.get(role, {}).get(permission, False)

def can_create_document_type(role, doc_type):
    if role in ['admin', 'general_director']:
        return True
    if role == 'secretary' and doc_type in ['order', 'cover_letter']:
        return True
    if role == 'department_head' and doc_type == 'service_note':
        return True
    if role == 'executor' and doc_type == 'service_note':
        return True
    return False

def can_perform_action(role, action):
    action_permissions = {
        'sign': 'can_sign_document',
        'encrypt': 'can_encrypt_document',
        'approve': 'can_approve_document',
        'review': 'can_review_document',
        'register': 'can_register_document',
        'send': 'can_send_document'
    }
    permission = action_permissions.get(action)
    return permission and has_permission(role, permission)

def can_view_document(user, document):
    if user.role == 'admin':
        return True
    if user.company_id == document.company_id:
        if user.role in ['general_director', 'secretary']:
            return True
        if document.author_id == user.id:
            return True
        # Проверяем назначение
        stage = DocumentStage.query.filter_by(
            document_id=document.id,
            assigned_to=user.id
        ).first()
        if stage:
            return True
        # Проверяем роль в маршруте
        route_config = json.loads(document.route_config) if document.route_config else []
        for stage in route_config:
            if stage['role'] == user.role:
                return True
    return False

def create_document_route(doc_type, company_id, author_id):
    route_config = DOCUMENT_ROUTES.get(doc_type, [])
    if not route_config:
        return json.dumps([])
    
    assigned_route = []
    for stage in route_config:
        user = User.query.filter_by(
            company_id=company_id,
            role=stage['role'],
            is_active=True
        ).first()
        
        assigned_stage = stage.copy()
        if user:
            assigned_stage['assigned_to'] = user.id
            assigned_stage['assigned_name'] = user.full_name
        else:
            assigned_stage['assigned_to'] = author_id
            assigned_stage['assigned_name'] = 'Автор документа'
        assigned_route.append(assigned_stage)
    
    return json.dumps(assigned_route)

def create_document_stages(document_id, route_config):
    for stage_data in route_config:
        stage = DocumentStage(
            document_id=document_id,
            stage_number=stage_data['stage'],
            role_required=stage_data['role'],
            assigned_to=stage_data.get('assigned_to'),
            action=stage_data['action'],
            status='pending'
        )
        db.session.add(stage)
    db.session.commit()

def log_audit(user_id, action, document_id=None, details=None):
    audit = AuditLog(
        user_id=user_id,
        action=action,
        document_id=document_id,
        details=details,
        ip_address=request.remote_addr
    )
    db.session.add(audit)
    db.session.commit()

# ===== FLASK =====
app = Flask(__name__)
app.config['SECRET_KEY'] = 'zedkd-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zedkd.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.context_processor
def utility_processor():
    return dict(
        has_permission=has_permission,
        can_create_document_type=can_create_document_type
    )

# ===== МАРШРУТЫ =====
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            if not user.is_active:
                flash('Учетная запись не активирована', 'error')
                return redirect(url_for('login'))
            
            login_user(user)
            log_audit(user.id, 'Вход в систему')
            flash('Вход выполнен успешно', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Неверный email или пароль', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        documents = Document.query.order_by(Document.created_at.desc()).limit(10).all()
    else:
        documents = Document.query.filter_by(company_id=current_user.company_id).order_by(Document.created_at.desc()).limit(10).all()
    
    my_documents = Document.query.filter_by(author_id=current_user.id).order_by(Document.created_at.desc()).limit(5).all()
    
    assigned_stages = DocumentStage.query.filter_by(
        assigned_to=current_user.id,
        status='pending'
    ).all()
    
    return render_template('dashboard.html', 
                         documents=documents,
                         my_documents=my_documents,
                         assigned_stages=assigned_stages)

@app.route('/logout')
@login_required
def logout():
    log_audit(current_user.id, 'Выход из системы')
    logout_user()
    flash('Вы вышли из системы', 'success')
    return redirect(url_for('index'))

@app.route('/register_company', methods=['GET', 'POST'])
def register_company():
    if request.method == 'POST':
        company = Company(
            name=request.form.get('company_name'),
            inn=request.form.get('inn'),
            status='pending'
        )
        db.session.add(company)
        db.session.commit()
        
        private_key, public_key = crypto.generate_key_pair()
        
        director = User(
            email=request.form.get('email'),
            full_name=request.form.get('full_name'),
            role='general_director',
            company_id=company.id,
            public_key=public_key,
            private_key_encrypted=private_key,
            is_active=False
        )
        director.set_password(request.form.get('password'))
        
        db.session.add(director)
        db.session.commit()
        
        company.director_id = director.id
        db.session.commit()
        
        log_audit(director.id, 'Регистрация компании', details=company.name)
        flash('Заявка отправлена. Ожидайте подтверждения.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register_company.html')

@app.route('/create_document', methods=['GET', 'POST'])
@login_required
def create_document():
    if not has_permission(current_user.role, 'can_create_document'):
        flash('Нет прав для создания документов', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        doc_type = request.form.get('doc_type')
        title = request.form.get('title')
        file = request.files.get('file')
        
        if not file:
            flash('Выберите файл', 'error')
            return redirect(url_for('create_document'))
        
        if not can_create_document_type(current_user.role, doc_type):
            flash('Нет прав на создание этого типа документа', 'error')
            return redirect(url_for('dashboard'))
        
        doc_uuid = str(uuid.uuid4())
        filename = f"{doc_uuid}_{file.filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        file.save(filepath)
        
        doc_hash = crypto.calculate_hash(filepath)
        
        route_config = create_document_route(doc_type, current_user.company_id, current_user.id)
        
        document = Document(
            uuid=doc_uuid,
            type=doc_type,
            title=title,
            file_path=filepath,
            original_hash=doc_hash,
            author_id=current_user.id,
            company_id=current_user.company_id,
            status='draft',
            route_config=route_config
        )
        
        db.session.add(document)
        db.session.commit()
        
        create_document_stages(document.id, json.loads(route_config))
        
        log_audit(current_user.id, 'Создание документа', document.id, f"Тип: {doc_type}")
        flash('Документ создан', 'success')
        
        return redirect(url_for('document_view', doc_id=document.id))
    
    return render_template('create_document.html')

@app.route('/document/<int:doc_id>')
@login_required
def document_view(doc_id):
    document = Document.query.get_or_404(doc_id)
    
    if not can_view_document(current_user, document):
        flash('Доступ запрещен', 'error')
        return redirect(url_for('dashboard'))
    
    route_config = json.loads(document.route_config) if document.route_config else []
    
    stages = DocumentStage.query.filter_by(document_id=doc_id).order_by(DocumentStage.stage_number).all()
    
    current_stage = DocumentStage.query.filter_by(
        document_id=doc_id,
        stage_number=document.current_stage
    ).first()
    
    return render_template('document_view.html', 
                         document=document, 
                         route_config=route_config,
                         stages=stages,
                         current_stage=current_stage)

@app.route('/process_document/<int:doc_id>', methods=['POST'])
@login_required
def process_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    action = request.form.get('action')
    comments = request.form.get('comments', '')
    
    current_stage = DocumentStage.query.filter_by(
        document_id=doc_id,
        stage_number=document.current_stage
    ).first()
    
    if not current_stage:
        flash('Этап не найден', 'error')
        return redirect(url_for('document_view', doc_id=doc_id))
    
    # Проверяем назначение
    if current_stage.assigned_to != current_user.id:
        # Если не назначен, проверяем может ли он выполнить действие
        if not can_perform_action(current_user.role, action):
            flash('Вы не назначены на этот этап', 'error')
            return redirect(url_for('document_view', doc_id=doc_id))
        # Автоматически назначаем если подходит по роли
        current_stage.assigned_to = current_user.id
        flash('Вы автоматически назначены на этот этап', 'info')
    
    if not can_perform_action(current_user.role, action):
        flash('Нет прав для этого действия', 'error')
        return redirect(url_for('document_view', doc_id=doc_id))
    
    if current_stage.action != action:
        flash('Неверное действие для этого этапа', 'error')
        return redirect(url_for('document_view', doc_id=doc_id))
    
    # Выполняем действие
    if action == 'sign':
        signature = crypto.sign_document(document.file_path, current_user.private_key_encrypted)
        current_stage.signature = signature
        current_stage.status = 'completed'
        current_stage.completed_at = datetime.utcnow()
        current_stage.comments = comments
        flash('Документ подписан', 'success')
        log_audit(current_user.id, 'Подписание документа', doc_id)
    
    elif action == 'encrypt':
        encrypted_path = crypto.encrypt_file(document.file_path, 'encryption_key')
        document.file_path = encrypted_path
        current_stage.status = 'completed'
        current_stage.completed_at = datetime.utcnow()
        current_stage.comments = comments
        flash('Документ зашифрован', 'success')
        log_audit(current_user.id, 'Шифрование документа', doc_id)
    
    elif action == 'approve':
        document.status = 'approved'
        current_stage.status = 'completed'
        current_stage.completed_at = datetime.utcnow()
        current_stage.comments = comments
        flash('Документ утвержден', 'success')
        log_audit(current_user.id, 'Утверждение документа', doc_id)
    
    elif action == 'review':
        current_stage.status = 'completed'
        current_stage.completed_at = datetime.utcnow()
        current_stage.comments = comments
        flash('Документ проверен', 'success')
        log_audit(current_user.id, 'Проверка документа', doc_id)
    
    elif action == 'register':
        current_stage.status = 'completed'
        current_stage.completed_at = datetime.utcnow()
        current_stage.comments = comments
        flash('Документ зарегистрирован', 'success')
        log_audit(current_user.id, 'Регистрация документа', doc_id)
    
    elif action == 'send':
        current_stage.status = 'completed'
        current_stage.completed_at = datetime.utcnow()
        current_stage.comments = comments
        flash('Документ отправлен', 'success')
        log_audit(current_user.id, 'Отправка документа', doc_id)
    
    # Переход к следующему этапу
    if current_stage.status == 'completed':
        if document.current_stage < len(json.loads(document.route_config)):
            document.current_stage += 1
            document.status = 'in_progress'
        else:
            document.status = 'completed'
            flash('Документ завершен', 'success')
    
    db.session.commit()
    return redirect(url_for('document_view', doc_id=doc_id))

@app.route('/documents')
@login_required
def documents_list():
    if current_user.role == 'admin':
        documents = Document.query.order_by(Document.created_at.desc()).all()
    else:
        documents = Document.query.filter_by(company_id=current_user.company_id).order_by(Document.created_at.desc()).all()
    
    return render_template('documents.html', documents=documents)

@app.route('/my_documents')
@login_required
def my_documents():
    documents = Document.query.filter_by(author_id=current_user.id).order_by(Document.created_at.desc()).all()
    return render_template('my_documents.html', documents=documents)

@app.route('/assigned_documents')
@login_required
def assigned_documents():
    stages = DocumentStage.query.filter_by(assigned_to=current_user.id, status='pending').all()
    document_ids = [stage.document_id for stage in stages]
    documents = Document.query.filter(Document.id.in_(document_ids)).all()
    return render_template('assigned_documents.html', documents=documents, stages=stages)

@app.route('/audit_log')
@login_required
def audit_log():
    if not has_permission(current_user.role, 'can_view_audit_log'):
        flash('Нет прав для просмотра журнала', 'error')
        return redirect(url_for('dashboard'))
    
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(1000).all()
    return render_template('audit_log.html', logs=logs)

@app.route('/security_dashboard')
@login_required
def security_dashboard():
    if not has_permission(current_user.role, 'can_view_security_dashboard'):
        flash('Нет прав для просмотра', 'error')
        return redirect(url_for('dashboard'))
    
    users_with_keys = User.query.filter(User.public_key.isnot(None)).count()
    documents_signed = Document.query.filter(Document.status.in_(['signed', 'completed'])).count()
    encrypted_docs = Document.query.filter(Document.file_path.like('%.enc')).count()
    
    return render_template('security_dashboard.html',
                         users_with_keys=users_with_keys,
                         documents_signed=documents_signed,
                         encrypted_docs=encrypted_docs)

@app.route('/sign_document/<int:doc_id>', methods=['GET', 'POST'])
@login_required
def sign_document(doc_id):
    if not has_permission(current_user.role, 'can_sign_document'):
        flash('Нет прав для подписания', 'error')
        return redirect(url_for('dashboard'))
    
    document = Document.query.get_or_404(doc_id)
    
    if not can_view_document(current_user, document):
        flash('Доступ запрещен', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        signature = crypto.sign_document(document.file_path, current_user.private_key_encrypted)
        document.status = 'signed'
        db.session.commit()
        
        log_audit(current_user.id, 'Подписание документа', doc_id)
        flash(f'Документ подписан', 'success')
        return redirect(url_for('document_view', doc_id=doc_id))
    
    return render_template('sign_document.html', document=document)

@app.route('/manage_companies')
@login_required
def manage_companies():
    if not has_permission(current_user.role, 'can_manage_companies'):
        flash('Нет прав для управления компаниями', 'error')
        return redirect(url_for('dashboard'))
    
    companies = Company.query.all()
    return render_template('manage_companies.html', companies=companies)

@app.route('/approve_company/<int:company_id>')
@login_required
def approve_company(company_id):
    if not has_permission(current_user.role, 'can_manage_companies'):
        flash('Нет прав', 'error')
        return redirect(url_for('dashboard'))
    
    company = Company.query.get_or_404(company_id)
    company.status = 'approved'
    
    director = User.query.get(company.director_id)
    if director:
        director.is_active = True
    
    db.session.commit()
    
    log_audit(current_user.id, 'Подтверждение компании', details=company.name)
    flash(f'Компания "{company.name}" подтверждена', 'success')
    return redirect(url_for('manage_companies'))

@app.route('/download_document/<int:doc_id>')
@login_required
def download_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    
    if not can_view_document(current_user, document):
        flash('Доступ запрещен', 'error')
        return redirect(url_for('dashboard'))
    
    if document.file_path.endswith('.enc'):
        decrypted_path = crypto.decrypt_file(document.file_path, 'encryption_key')
        
        if decrypted_path and os.path.exists(decrypted_path):
            log_audit(current_user.id, 'Скачивание документа', doc_id, 'расшифрованная версия')
            return send_file(decrypted_path, as_attachment=True, 
                           download_name=f'document_{document.uuid}_decrypted')
    
    if os.path.exists(document.file_path):
        log_audit(current_user.id, 'Скачивание документа', doc_id)
        return send_file(document.file_path, as_attachment=True, 
                       download_name=f'document_{document.uuid}')
    
    flash('Файл не найден', 'error')
    return redirect(url_for('document_view', doc_id=doc_id))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    
    if not current_user.check_password(current_password):
        flash('Текущий пароль неверен', 'error')
        return redirect(url_for('profile'))
    
    current_user.set_password(new_password)
    db.session.commit()
    
    log_audit(current_user.id, 'Смена пароля')
    flash('Пароль изменен', 'success')
    return redirect(url_for('profile'))

# ===== ИНИЦИАЛИЗАЦИЯ =====
def init_database():
    with app.app_context():
        db.create_all()
        
        # Админ
        if not User.query.filter_by(email='admin@zedkd.ru').first():
            admin = User(
                email='admin@zedkd.ru',
                full_name='Администратор системы',
                role='admin',
                is_active=True
            )
            admin.set_password('admin123')
            private_key, public_key = crypto.generate_key_pair()
            admin.public_key = public_key
            admin.private_key_encrypted = private_key
            
            db.session.add(admin)
            db.session.commit()
            print("✓ Админ: admin@zedkd.ru / admin123")
        
        # Компания 1
        if not Company.query.filter_by(name='ООО "ТехноПром"').first():
            company = Company(
                name='ООО "ТехноПром"',
                inn='1234567890',
                status='approved'
            )
            db.session.add(company)
            db.session.commit()
            
            # Тестовые пользователи
            test_users = [
                ('director@company1.ru', 'director123', 'Иванов Иван Иванович', 'general_director'),
                ('secretary@company1.ru', 'secretary123', 'Петрова Анна Сергеевна', 'secretary'),
                ('department.head@company1.ru', 'head123', 'Сидоров Петр Васильевич', 'department_head'),
                ('executor@company1.ru', 'executor123', 'Кузнецова Ольга Дмитриевна', 'executor'),
                ('approver@company1.ru', 'approver123', 'Морозов Сергей Александрович', 'approver'),
                ('courier@company1.ru', 'courier123', 'Тарасов Денис Игоревич', 'courier'),
            ]
            
            for email, password, name, role in test_users:
                if not User.query.filter_by(email=email).first():
                    user = User(
                        email=email,
                        full_name=name,
                        role=role,
                        company_id=company.id,
                        is_active=True
                    )
                    user.set_password(password)
                    private_key, public_key = crypto.generate_key_pair()
                    user.public_key = public_key
                    user.private_key_encrypted = private_key
                    
                    db.session.add(user)
            
            db.session.commit()
            
            director = User.query.filter_by(email='director@company1.ru').first()
            if director:
                company.director_id = director.id
            
            db.session.commit()
            print("✓ Тестовые пользователи созданы")

if __name__ == '__main__':
    if os.path.exists('zedkd.db'):
        os.remove('zedkd.db')
        print("Старая база удалена")
    
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    
    init_database()
    
    print("\n" + "="*50)
    print("ЗЭДКД - Готов к работе!")
    print("="*50)
    print("\nЛогины и пароли:")
    print("  Админ: admin@zedkd.ru / admin123")
    print("  Директор: director@company1.ru / director123")
    print("  Секретарь: secretary@company1.ru / secretary123")
    print("  Руководитель отдела: department.head@company1.ru / head123")
    print("  Исполнитель: executor@company1.ru / executor123")
    print("  Утверждающий: approver@company1.ru / approver123")
    print("  Курьер: courier@company1.ru / courier123")
    print("\nИсполнитель может:")
    print("  1. Создавать служебные записки")
    print("  2. Шифровать документы на этапе 'encrypt'")
    print("  3. Отправлять документы на этапе 'send'")
    print("\n" + "="*50)
    
    app.run(debug=True, port=5000)