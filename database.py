# database.py - обновленная версия
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import json

db = SQLAlchemy()

# Роли пользователей (10 ролей как требовалось)
ROLES = [
    'admin',                    # Администратор системы
    'general_director',         # Генеральный директор
    'secretary',               # Секретарь/делопроизводитель
    'department_head',         # Руководитель отдела
    'executor',                # Исполнитель
    'controller',              # Контролер
    'archivist',               # Архивариус
    'courier',                 # Курьер
    'reviewer',                # Рецензент
    'approver'                 # Утверждающий
]

class Company(db.Model):
    __tablename__ = 'companies'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    inn = db.Column(db.String(12), unique=True, nullable=False)
    director_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    status = db.Column(db.Enum('pending', 'approved', 'rejected'), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Связи
    users = db.relationship('User', backref='company', lazy=True)
    documents = db.relationship('Document', backref='company', lazy=True)

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(150), nullable=False)
    role = db.Column(db.Enum(*ROLES), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'))
    public_key = db.Column(db.Text)  # Публичный ключ для ЭЦП
    private_key_encrypted = db.Column(db.Text)  # Зашифрованный приватный ключ
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Связи
    created_documents = db.relationship('Document', foreign_keys='Document.author_id', backref='author', lazy=True)
    assigned_stages = db.relationship('DocumentStage', foreign_keys='DocumentStage.assigned_to', backref='assignee', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Document(db.Model):
    __tablename__ = 'documents'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    type = db.Column(db.Enum('service_note', 'order', 'cover_letter'), nullable=False)
    title = db.Column(db.String(500), nullable=False)
    file_path = db.Column(db.String(500))  # Путь к зашифрованному файлу
    original_hash = db.Column(db.String(64))  # Хэш оригинального документа
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    current_stage = db.Column(db.Integer, default=1)
    status = db.Column(db.Enum('draft', 'in_progress', 'signed', 'rejected', 'completed', 'archived'), default='draft')
    route_config = db.Column(db.JSON)  # Конфигурация маршрута
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Связи
    stages = db.relationship('DocumentStage', backref='document', lazy=True, order_by='DocumentStage.stage_number')
    media_records = db.relationship('MediaLog', backref='document', lazy=True)

class DocumentStage(db.Model):
    __tablename__ = 'document_stages'
    
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
    stage_number = db.Column(db.Integer, nullable=False)
    role_required = db.Column(db.String(50), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.Enum('sign', 'encrypt', 'review', 'approve', 'register', 'send'), nullable=False)
    status = db.Column(db.Enum('pending', 'in_progress', 'completed', 'rejected'), default='pending')
    signature = db.Column(db.Text)  # ЭЦП этапа
    encrypted_key = db.Column(db.Text)  # Ключ шифрования для этапа
    comments = db.Column(db.Text)
    completed_at = db.Column(db.DateTime)
    deadline = db.Column(db.Date)
    
    # Виртуальное поле для получения пользователя
    assigned_user = db.relationship('User', foreign_keys=[assigned_to])

class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    ip_address = db.Column(db.String(45))
    action = db.Column(db.String(100), nullable=False)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'))
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Связи
    user = db.relationship('User', backref='audit_logs')

class MediaLog(db.Model):
    __tablename__ = 'media_log'
    
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
    pages = db.Column(db.Integer)  # 100 сброшюрованных листов
    copies = db.Column(db.Integer)  # 3 экземпляра
    recipient_addresses = db.Column(db.JSON)  # 2 адреса
    carrier_type = db.Column(db.String(50))
    carrier_number = db.Column(db.String(100))
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Связи
    creator = db.relationship('User', foreign_keys=[created_by])