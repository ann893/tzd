# routes_config.py
DOCUMENT_ROUTES = {
    # СЛУЖЕБНАЯ ЗАПИСКА (3 этапа)
    'service_note': [
        {
            'stage': 1,
            'role': 'department_head',
            'action': 'review',
            'title': 'Согласование руководителем отдела',
            'crypto_action': 'sign'  # Подпись документа
        },
        {
            'stage': 2,
            'role': 'reviewer',
            'action': 'sign',
            'title': 'Визирование',
            'crypto_action': 'sign'  # Дополнительная подпись
        },
        {
            'stage': 3,
            'role': 'executor',
            'action': 'encrypt',
            'title': 'Исполнение и шифрование',
            'crypto_action': 'encrypt'  # Шифрование документа
        }
    ],
    
    # ПРИКАЗ (5 этапов) - оборот приказа
    'order': [
        {
            'stage': 1,
            'role': 'secretary',
            'action': 'register',
            'title': 'Регистрация приказа',
            'crypto_action': 'sign'
        },
        {
            'stage': 2,
            'role': 'department_head',
            'action': 'review',
            'title': 'Согласование с руководителем',
            'crypto_action': 'sign'
        },
        {
            'stage': 3,
            'role': 'reviewer',
            'action': 'review',
            'title': 'Юридическая экспертиза',
            'crypto_action': 'sign'
        },
        {
            'stage': 4,
            'role': 'approver',
            'action': 'approve',
            'title': 'Утверждение генеральным директором',
            'crypto_action': 'sign'
        },
        {
            'stage': 5,
            'role': 'executor',
            'action': 'send',
            'title': 'Отправка исполнителям',
            'crypto_action': 'encrypt'
        }
    ],
    
    # СОПРОВОДИТЕЛЬНОЕ ПИСЬМО (8 этапов) - ваш вариант
    'cover_letter': [
        {
            'stage': 1,
            'role': 'secretary',
            'action': 'register',
            'title': 'Регистрация письма',
            'crypto_action': 'sign'
        },
        {
            'stage': 2,
            'role': 'department_head',
            'action': 'review',
            'title': 'Проверка содержания',
            'crypto_action': 'sign'
        },
        {
            'stage': 3,
            'role': 'controller',
            'action': 'review',
            'title': 'Контроль соответствия',
            'crypto_action': 'sign'
        },
        {
            'stage': 4,
            'role': 'approver',
            'action': 'approve',
            'title': 'Утверждение',
            'crypto_action': 'sign'
        },
        {
            'stage': 5,
            'role': 'executor',
            'action': 'encrypt',
            'title': 'Подготовка и шифрование',
            'crypto_action': 'encrypt'
        },
        {
            'stage': 6,
            'role': 'archivist',
            'action': 'register',
            'title': 'Внесение в журнал учета',
            'crypto_action': 'sign'
        },
        {
            'stage': 7,
            'role': 'courier',
            'action': 'send',
            'title': 'Подготовка к отправке',
            'crypto_action': None
        },
        {
            'stage': 8,
            'role': 'secretary',
            'action': 'send',
            'title': 'Отправка по адресам',
            'crypto_action': None
        }
    ]
}

# Функция для создания маршрута документа
def create_document_route(doc_type, company_id, author_id):
    """Создает маршрут для документа с назначением пользователей"""
    from database import User, db
    import uuid
    
    route_config = DOCUMENT_ROUTES.get(doc_type)
    if not route_config:
        return None
    
    # Для каждого этапа находим подходящего пользователя
    route_with_users = []
    for stage in route_config:
        # Находим пользователя с нужной ролью в компании
        user = User.query.filter_by(
            company_id=company_id,
            role=stage['role'],
            is_active=True
        ).first()
        
        if user:
            route_with_users.append({
                **stage,
                'assigned_to': user.id,
                'assigned_name': user.full_name
            })
        else:
            # Если пользователь не найден, оставляем этап без назначения
            route_with_users.append({
                **stage,
                'assigned_to': None,
                'assigned_name': 'Не назначен'
            })
    
    return route_with_users