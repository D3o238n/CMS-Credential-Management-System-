-- Создание таблицы пользователей
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user', -- user, admin, developer, devops
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Создание таблицы секретов
CREATE TABLE IF NOT EXISTS secrets (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- password, api_key, token, certificate, ssh_key
    encrypted_value TEXT NOT NULL,
    description TEXT,
    tags JSONB,
    owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    version INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL,
    UNIQUE(name, owner_id)
);

-- Создание таблицы версий секретов (история изменений)
CREATE TABLE IF NOT EXISTS secret_versions (
    id SERIAL PRIMARY KEY,
    secret_id INTEGER REFERENCES secrets(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    encrypted_value TEXT NOT NULL,
    updated_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Создание таблицы аудита
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    user_email VARCHAR(255) NOT NULL,
    action VARCHAR(50) NOT NULL, -- CREATE, VIEW, UPDATE, DELETE, ROTATE, LOGIN
    secret_id INTEGER,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Индексы для оптимизации запросов
CREATE INDEX idx_secrets_owner ON secrets(owner_id);
CREATE INDEX idx_secrets_name ON secrets(name);
CREATE INDEX idx_secrets_deleted ON secrets(deleted_at);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_created ON audit_logs(created_at);
CREATE INDEX idx_secret_versions_secret ON secret_versions(secret_id);

-- Триггер для автоматического обновления updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_secrets_updated_at BEFORE UPDATE ON secrets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Вставка тестового администратора (пароль: admin123)
-- Hash для пароля 'admin123'
INSERT INTO users (email, password_hash, full_name, role) 
VALUES (
    'admin@company.com',
    E'$2b$12$j2GMquZhi3Q3kPf3luW5QeAqeWqAck2Mn4iIZD.movowSkpMTM3dW',
    'System Administrator',
    'admin'
) ON CONFLICT (email) DO NOTHING;

-- Вставка тестового разработчика (пароль: dev123)
INSERT INTO users (email, password_hash, full_name, role) 
VALUES (
    'developer@company.com',
    E'$2b$12$Fny.U5ef6G4PQnfXCpZibePgVaHJSvyLJ1kJObv0G0z7I1IIwK4Me',
    'John Developer',
    'developer'
) ON CONFLICT (email) DO NOTHING;

-- Комментарии к таблицам
COMMENT ON TABLE users IS 'Пользователи системы';
COMMENT ON TABLE secrets IS 'Хранилище зашифрованных секретов';
COMMENT ON TABLE secret_versions IS 'История изменений секретов';
COMMENT ON TABLE audit_logs IS 'Журнал аудита всех действий';

-- Вывод информации
DO $$
BEGIN
    RAISE NOTICE '✅ База данных инициализирована успешно!';
    RAISE NOTICE '📊 Созданы таблицы: users, secrets, secret_versions, audit_logs';
    RAISE NOTICE '👤 Тестовые пользователи:';
    RAISE NOTICE '   - admin@company.com / admin123 (Administrator)';
    RAISE NOTICE '   - developer@company.com / dev123 (Developer)';
END $$;