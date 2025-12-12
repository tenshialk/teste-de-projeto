from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, DecimalField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-change-me'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecommerce.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(30))
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    orders = db.relationship('Order', backref='user', lazy=True)
    reviews = db.relationship('Review', backref='user', lazy=True)
    tickets = db.relationship('SupportTicket', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=True)
    brand = db.Column(db.String(100), nullable=True)
    price = db.Column(db.Numeric(10,2), nullable=False)
    stock = db.Column(db.Integer, default=0)
    description = db.Column(db.Text)
    reviews = db.relationship('Review', backref='product', lazy=True)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_number = db.Column(db.String(50), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='Processando')
    total = db.Column(db.Numeric(10,2))
    items = db.relationship('OrderItem', backref='order', lazy=True)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Numeric(10,2), nullable=False)
    product = db.relationship('Product')

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    rating = db.Column(db.Integer)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SupportTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    subject = db.Column(db.String(200))
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='Aberto')

# Forms
class RegisterForm(FlaskForm):
    name = StringField('Nome', validators=[DataRequired(), Length(min=2)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Telefone')
    password = PasswordField('Senha', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Confirmar Senha', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Cadastrar')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError('Email já cadastrado.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')

class SupportForm(FlaskForm):
    subject = StringField('Assunto', validators=[DataRequired()])
    message = TextAreaField('Mensagem', validators=[DataRequired(), Length(min=10)])
    submit = SubmitField('Enviar')

class ReviewForm(FlaskForm):
    rating = IntegerField('Nota (1-5)', validators=[DataRequired(), NumberRange(min=1, max=5)])
    comment = TextAreaField('Comentário')
    submit = SubmitField('Enviar Avaliação')

# login loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helpers
import random, string

def generate_order_number():
    return 'ORD-' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

# Routes
@app.route('/')
def index():
    q = request.args.get('q', '')
    category = request.args.get('category', '')
    products = Product.query
    if q:
        products = products.filter(Product.name.ilike(f'%{q}%'))
    if category:
        products = products.filter(Product.category==category)
    products = products.limit(50).all()
    categories = db.session.query(Product.category).distinct().all()
    return render_template('index.html', products=products, categories=[c[0] for c in categories])

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    form = ReviewForm()
    return render_template('product.html', product=product, form=form)

@app.route('/add_review/<int:product_id>', methods=['POST'])
@login_required
def add_review(product_id):
    form = ReviewForm()
    if form.validate_on_submit():
        # check if user bought the product
        bought = OrderItem.query.join(Order).filter(Order.user_id==current_user.id, OrderItem.product_id==product_id).first()
        if not bought:
            flash('Só é possível avaliar produtos já comprados.', 'danger')
            return redirect(url_for('product_detail', product_id=product_id))
        review = Review(user_id=current_user.id, product_id=product_id, rating=form.rating.data, comment=form.comment.data)
        db.session.add(review)
        db.session.commit()
        flash('Avaliação enviada com sucesso.', 'success')
    else:
        flash('Erro ao enviar avaliação.', 'danger')
    return redirect(url_for('product_detail', product_id=product_id))

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(name=form.name.data, email=form.email.data.lower(), phone=form.phone.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Cadastro realizado com sucesso.', 'success')
        return redirect(url_for('account'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if not user:
            flash('Email não encontrado.', 'danger')
            return redirect(url_for('login'))
        if not user.check_password(form.password.data):
            flash('Senha incorreta.', 'danger')
            return redirect(url_for('login'))
        login_user(user)
        flash('Login realizado com sucesso.', 'success')
        return redirect(url_for('account'))
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Desconectado.', 'info')
    return redirect(url_for('index'))

@app.route('/account')
@login_required
def account():
    return render_template('account.html')

# Cart stored in session
@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    qty = int(request.form.get('quantity', 1))
    if qty < 1:
        qty = 1
    if qty > product.stock:
        flash('Quantidade solicitada maior que o estoque.', 'danger')
        return redirect(url_for('product_detail', product_id=product_id))
    cart = session.get('cart', {})
    cart[str(product_id)] = cart.get(str(product_id), 0) + qty
    if cart[str(product_id)] > product.stock:
        cart[str(product_id)] = product.stock
        flash('Quantidade ajustada ao estoque disponível.', 'warning')
    session['cart'] = cart
    flash('Produto adicionado ao carrinho.', 'success')
    return redirect(url_for('cart'))

@app.route('/cart')
def cart():
    cart = session.get('cart', {})
    items = []
    total = 0
    for pid, qty in cart.items():
        p = Product.query.get(int(pid))
        if not p: continue
        subtotal = float(p.price) * int(qty)
        items.append({'product': p, 'quantity': qty, 'subtotal': subtotal})
        total += subtotal
    return render_template('cart.html', items=items, total=total)

@app.route('/update_cart', methods=['POST'])
def update_cart():
    cart = session.get('cart', {})
    for pid, qty in request.form.items():
        if not pid.startswith('qty_'): continue
        product_id = pid.split('_',1)[1]
        try:
            q = int(qty)
        except:
            q = 1
        p = Product.query.get(int(product_id))
        if not p: continue
        if q <= 0:
            cart.pop(product_id, None)
        else:
            cart[product_id] = min(q, p.stock)
    session['cart'] = cart
    flash('Carrinho atualizado.', 'success')
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET','POST'])
@login_required
def checkout():
    cart = session.get('cart', {})
    if not cart:
        flash('Carrinho vazio. Não é possível finalizar a compra.', 'danger')
        return redirect(url_for('cart'))
    # For simplicity, require address input via form or use dummy address
    if request.method == 'POST':
        payment_method = request.form.get('payment_method')
        if not payment_method:
            flash('Selecione um método de pagamento.', 'danger')
            return redirect(url_for('checkout'))
        # compute total and create order
        total = 0
        order = Order(order_number=generate_order_number(), user_id=current_user.id, status='Processando')
        db.session.add(order)
        db.session.flush()
        for pid, qty in cart.items():
            p = Product.query.get(int(pid))
            if not p: continue
            if int(qty) > p.stock:
                flash(f'Estoque insuficiente para {p.name}.', 'danger')
                db.session.rollback()
                return redirect(url_for('cart'))
            item = OrderItem(order_id=order.id, product_id=p.id, quantity=qty, price=p.price)
            p.stock -= int(qty)
            db.session.add(item)
            total += float(p.price) * int(qty)
        order.total = total
        db.session.commit()
        session.pop('cart', None)
        flash('Pedido realizado com sucesso.', 'success')
        return redirect(url_for('order_detail', order_id=order.id))
    return render_template('checkout.html')

@app.route('/orders')
@login_required
def orders():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template('orders.html', orders=orders)

@app.route('/order/<int:order_id>')
@login_required
def order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        flash('Acesso negado.', 'danger')
        return redirect(url_for('orders'))
    return render_template('order_detail.html', order=order)

@app.route('/support', methods=['GET','POST'])
@login_required
def support():
    form = SupportForm()
    if form.validate_on_submit():
        ticket = SupportTicket(user_id=current_user.id, subject=form.subject.data, message=form.message.data)
        db.session.add(ticket)
        db.session.commit()
        flash('Solicitação enviada. Em breve nossa equipe entrará em contato.', 'success')
        return redirect(url_for('support'))
    tickets = SupportTicket.query.filter_by(user_id=current_user.id).order_by(SupportTicket.created_at.desc()).all()
    return render_template('support.html', form=form, tickets=tickets)

@app.route('/return_policy')
def return_policy():
    # static page
    return render_template('return_policy.html')

# Admin-like route to seed products (DEV)
@app.route('/seed')
def seed():
    if Product.query.first():
        return 'Já semeado.'
    sample = [
        {'name':'Livro Python Básico','category':'Livros','brand':'Editorial X','price':39.90,'stock':10},
        {'name':'Mouse Óptico','category':'Informática','brand':'Marca Y','price':59.90,'stock':25},
        {'name':'Caderno 100 Folhas','category':'Papelaria','brand':'Marca Z','price':9.90,'stock':100},
    ]
    for s in sample:
        p = Product(name=s['name'], category=s['category'], brand=s['brand'], price=s['price'], stock=s['stock'])
        db.session.add(p)
    db.session.commit()
    return 'Produtos criados.'

if __name__ == '__main__':
    if not os.path.exists('ecommerce.db'):
        db.create_all()
    app.run(debug=True)