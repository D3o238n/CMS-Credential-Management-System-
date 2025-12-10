from flask import Flask, render_template, request, redirect, url_for, session, flash
import requests
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

API_URL = os.getenv('API_URL', 'http://api-gateway')

@app.route('/')
def index():
    if 'token' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            response = requests.post(
                f'{API_URL}/api/auth/login',
                json={'email': email, 'password': password},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                session['token'] = data['access_token']
                session['user'] = {
                    'id': data.get('user_id'),
                    'email': data.get('email'),
                    'role': data.get('role', 'user'),
                    'full_name': data.get('full_name', email)
                }
                flash('Успешный вход!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Неверный email или пароль', 'error')
        except requests.exceptions.ConnectionError:
            flash('Ошибка подключения к серверу. Проверьте что все сервисы запущены.', 'error')
        except Exception as e:
            flash(f'Ошибка: {str(e)}', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'token' not in session:
        return redirect(url_for('login'))
    
    # USER не видит кнопку "Создать секрет"
    can_create = session.get('user', {}).get('role') in ['admin', 'developer']
    
    try:
        response = requests.get(
            f'{API_URL}/api/secrets',
            headers={'Authorization': f'Bearer {session["token"]}'},
            timeout=10
        )
        
        if response.status_code == 200:
            secrets = response.json()
            return render_template('dashboard.html', secrets=secrets, user=session.get('user'), can_create=can_create)
        elif response.status_code == 401:
            session.clear()
            flash('Сессия истекла', 'warning')
            return redirect(url_for('login'))
        else:
            flash('Ошибка загрузки секретов', 'error')
            return render_template('dashboard.html', secrets=[], user=session.get('user'), can_create=can_create)
    except Exception as e:
        flash(f'Ошибка: {str(e)}', 'error')
        return render_template('dashboard.html', secrets=[], user=session.get('user'), can_create=can_create)

@app.route('/secrets/create', methods=['GET', 'POST'])
def create_secret():
    if 'token' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            tags = request.form.get('tags', '').split(',')
            tags = [tag.strip() for tag in tags if tag.strip()]
            
            response = requests.post(
                f'{API_URL}/api/secrets',
                headers={'Authorization': f'Bearer {session["token"]}'},
                json={
                    'name': request.form.get('name'),
                    'type': request.form.get('type'),
                    'value': request.form.get('value'),
                    'description': request.form.get('description'),
                    'tags': tags
                },
                timeout=10
            )
            
            if response.status_code == 200:
                flash('Секрет создан успешно!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Ошибка создания секрета', 'error')
        except Exception as e:
            flash(f'Ошибка: {str(e)}', 'error')
    
    return render_template('create_secret.html', user=session.get('user'))

@app.route('/secrets/<int:secret_id>')
def view_secret(secret_id):
    if 'token' not in session:
        return redirect(url_for('login'))
    
    show_value = request.args.get('show_value', 'false') == 'true'
    
    try:
        response = requests.get(
            f'{API_URL}/api/secrets/{secret_id}?show_value={show_value}',
            headers={'Authorization': f'Bearer {session["token"]}'},
            timeout=10
        )
        
        if response.status_code == 200:
            secret = response.json()
            
            versions_response = requests.get(
                f'{API_URL}/api/secrets/{secret_id}/versions',
                headers={'Authorization': f'Bearer {session["token"]}'},
                timeout=10
            )
            versions = versions_response.json() if versions_response.status_code == 200 else []
            
            return render_template('view_secret.html', secret=secret, versions=versions, user=session.get('user'))
        else:
            flash('Секрет не найден', 'error')
            return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Ошибка: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/secrets/<int:secret_id>/delete', methods=['POST'])
def delete_secret(secret_id):
    if 'token' not in session:
        return redirect(url_for('login'))
    
    try:
        response = requests.delete(
            f'{API_URL}/api/secrets/{secret_id}',
            headers={'Authorization': f'Bearer {session["token"]}'},
            timeout=10
        )
        
        if response.status_code == 200:
            flash('Секрет удален', 'success')
        else:
            flash('Ошибка удаления', 'error')
    except Exception as e:
        flash(f'Ошибка: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/secrets/<int:secret_id>/rotate', methods=['POST'])
def rotate_secret(secret_id):
    if 'token' not in session:
        return redirect(url_for('login'))
    
    try:
        response = requests.post(
            f'{API_URL}/api/secrets/{secret_id}/rotate',
            headers={'Authorization': f'Bearer {session["token"]}'},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            flash(f'Секрет обновлен! Новое значение: {data.get("new_value")}', 'success')
        else:
            flash('Ошибка ротации', 'error')
    except Exception as e:
        flash(f'Ошибка: {str(e)}', 'error')
    
    return redirect(url_for('view_secret', secret_id=secret_id))

@app.route('/audit')
def audit_logs():
    if 'token' not in session:
        return redirect(url_for('login'))
    
    try:
        response = requests.get(f'{API_URL}/api/audit?limit=100', timeout=10)
        
        if response.status_code == 200:
            logs = response.json()
            return render_template('audit.html', logs=logs, user=session.get('user'))
        else:
            flash('Ошибка загрузки логов', 'error')
            return render_template('audit.html', logs=[], user=session.get('user'))
    except Exception as e:
        flash(f'Ошибка: {str(e)}', 'error')
        return render_template('audit.html', logs=[], user=session.get('user'))

@app.route('/admin/create-user', methods=['GET', 'POST'])
def create_user():
    if 'token' not in session:
        return redirect(url_for('login'))
    
    if session.get('user', {}).get('role') != 'admin':
        flash('Доступ запрещён. Только для администраторов.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            response = requests.post(
                f'{API_URL}/api/auth/register',
                json={
                    'email': request.form.get('email'),
                    'password': request.form.get('password'),
                    'full_name': request.form.get('full_name'),
                    'role': request.form.get('role', 'user')
                },
                timeout=10
            )
            
            if response.status_code == 200:
                flash(f'Пользователь {request.form.get("email")} создан!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Ошибка создания пользователя', 'error')
        except Exception as e:
            flash(f'Ошибка: {str(e)}', 'error')
    
    return render_template('admin_create_user.html', user=session.get('user'))

@app.route('/health')
def health():
    return {'status': 'healthy', 'service': 'web-ui'}, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)