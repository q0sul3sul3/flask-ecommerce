import json
import os
import secrets
import uuid

import boto3
import stripe
from botocore.exceptions import ClientError
from flask import flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.utils import secure_filename

from . import app, csrf, db
from .email import send_email
from .forms import (
    AddItemForm,
    LoginForm,
    RegisterForm,
    ResetPasswodRequestForm,
    ResetPasswordForm,
    SearchForm,
)
from .models import Category, Item, Order, User


@app.route('/')
@app.route('/shop/all')
def index():
    pagination = Item.query.paginate(
        page=int(request.args.get('page', 1)), per_page=6, error_out=False
    )
    items = pagination.items

    prev_num = pagination.prev_num
    prev_url = url_for('index', page=prev_num) if pagination.has_prev else None
    next_num = pagination.next_num
    next_url = url_for('index', page=next_num) if pagination.has_next else None
    return render_template(
        'index.html',
        items=items,
        prev_url=prev_url,
        next_url=next_url,
        bucket=app.config['AWS_BUCKET_NAME'],
        region=app.config['AWS_REGION_NAME'],
    )


@app.route('/shop/category/<string:slug>')
def category(slug):
    category = Category.query.filter_by(slug=slug).first_or_404()
    pagination = category.items.paginate(
        page=int(request.args.get('page', 1)), per_page=9, error_out=False
    )
    items = pagination.items
    return render_template('index.html', items=items)


@app.context_processor
def categories():
    categories = Category.query.all()
    return dict(categories=categories)


@app.route('/shop/item/<string:item_id>')
def item(item_id):
    item = Item.query.get_or_404(ident=item_id)
    return render_template(
        'item.html',
        item=item,
        bucket=app.config['AWS_BUCKET_NAME'],
        region=app.config['AWS_REGION_NAME'],
    )


@app.route('/add-item', methods=['GET', 'POST'])
def add_item():
    # Basic permission management
    if not (current_user.is_authenticated and current_user.id == 1):
        return redirect(url_for('index'))

    form = AddItemForm()
    if form.validate_on_submit():
        f = form.image.data  # f = request.files['image']
        extension = secure_filename(f.filename).split('.')[-1]
        filename = str(uuid.uuid4()) + '.' + extension

        try:
            s3 = boto3.client(
                's3',
                aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],
                aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY'],
            )
            s3.upload_fileobj(f, app.config['AWS_BUCKET_NAME'], filename)
        except ClientError as e:
            flash(f'Failed to upload image to S3: {str(e)}', 'danger')
            return render_template('add_item.html', form=form)
        else:
            item = Item(
                name=form.name.data,
                price=form.price.data,
                description=form.description.data,
                category=form.category.data,
                image=filename,
            )
            db.session.add(item)
            db.session.commit()
            flash(f'{form.name.data} added successfully!', 'success')
            return redirect(url_for('index'))

    return render_template('add_item.html', form=form)


@app.context_processor
def base():
    search_form = SearchForm()
    return dict(search_form=search_form)


@app.route('/search', methods=['POST'])
def search():
    form = SearchForm()
    if form.validate_on_submit():
        keyword = form.search.data
        items = Item.query.filter(Item.name.ilike('%' + keyword + '%'))
        return render_template('index.html', items=items)


@app.context_processor
def get_cart_quantity():
    if 'cart' not in session:
        return {'cart_quantity': 0}

    cart_quantity = 0
    if 'cart' in session:
        for j in session['cart'].values():
            cart_quantity += j['quantity']
        return {'cart_quantity': cart_quantity}


@app.route('/cart')
@login_required
def cart():
    if 'cart' not in session:
        session['cart'] = {}
        return render_template('cart.html', total=0)

    total = 0
    if 'cart' in session:
        for i in session['cart'].values():
            total += i['price'] * i['quantity']
        return render_template(
            'cart.html',
            total=total,
            bucket=app.config['AWS_BUCKET_NAME'],
            region=app.config['AWS_REGION_NAME'],
        )


@app.route('/cart/add', methods=['POST'])
def add_cart():
    item_id = request.form.get('item_id')
    item_quantity = int(request.form.get('item_quantity'))
    item = Item.query.filter_by(id=item_id).first_or_404()
    item_dict = {
        item_id: {
            'name': item.name,
            'price': item.price,
            'quantity': item_quantity,
            'image': item.image,
        }
    }

    # Check if the user has already started a cart.
    if 'cart' not in session:
        session['cart'] = item_dict
        return redirect(request.referrer)

    if 'cart' in session:
        if item_id in session['cart']:
            session['cart'][item_id]['quantity'] += item_quantity
        else:
            session['cart'].update(item_dict)
        session.modified = True
        return redirect(request.referrer)


@app.route('/cart/update', methods=['POST'])
def update_cart():
    data = request.get_json()
    item_id = str(data['id'])
    item_quantity = data['quantity']
    session['cart'][item_id]['quantity'] = item_quantity
    session.modified = True
    return {}


@app.route('/cart/delete', methods=['POST'])
def delete_cart():
    data = request.get_json()
    item_id = str(data['id'])
    session['cart'].pop(str(item_id))
    session.modified = True
    return {}


@csrf.exempt
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    if not session['cart']:
        flash('Your shopping cart is empty!', 'danger')
        return redirect(url_for('cart'))

    line_items = []
    for i, j in session['cart'].items():
        data = {
            'price_data': {
                'currency': 'twd',
                'unit_amount': j['price'] * 100,
                'product_data': {'name': j['name'], 'metadata': {'id': i}},
            },
            'quantity': j['quantity'],
        }
        line_items.append(data)

    try:
        checkout_session = stripe.checkout.Session.create(
            shipping_address_collection={"allowed_countries": ["TW"]},
            shipping_options=[
                {
                    "shipping_rate_data": {
                        "type": "fixed_amount",
                        "fixed_amount": {"amount": 0, "currency": "TWD"},
                        "display_name": "Free shipping",
                        "delivery_estimate": {
                            "minimum": {"unit": "business_day", "value": 5},
                            "maximum": {"unit": "business_day", "value": 7},
                        },
                    },
                },
                {
                    "shipping_rate_data": {
                        "type": "fixed_amount",
                        "fixed_amount": {"amount": 10000, "currency": "TWD"},
                        "display_name": "Next day delivery",
                        "delivery_estimate": {
                            "minimum": {"unit": "business_day", "value": 1},
                            "maximum": {"unit": "business_day", "value": 1},
                        },
                    },
                },
            ],
            line_items=line_items,
            metadata={
                'user_id': current_user.id,
                'cart': json.dumps(session['cart']),
            },
            customer_email=current_user.email,  # Prefill customer's email
            payment_method_types=['card'],
            mode='payment',
            # If set _external to True, an absolute URL is generated.
            success_url=url_for('success', _external=True)
            + '?id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('index', _external=True),
        )
    except stripe.error.InvalidRequestError as e:
        flash('Total amount must be less than $999,999.99.', 'danger')
        return redirect(url_for('cart'))
    else:
        session['cart'] = {}
        session.modified = True
        return redirect(checkout_session.url, code=303)


@csrf.exempt
@app.route('/webhook', methods=['POST'])
def webhook():
    event = None
    payload = request.get_data()
    sig_header = request.environ.get('HTTP_STRIPE_SIGNATURE')

    # This is your Stripe webhook secret.
    endpoint_secret = app.config['ENDPOINT_SECRET']

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except ValueError as e:
        # Invalid payload
        return {'error': 'Invalid payload'}, 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return {'error': 'Invalid signature'}, 400

    # Handle the checkout.session.completed event
    if event['type'] == 'checkout.session.completed':
        # Retrieve the session. If you require line items in the response, you may include them by expanding line_items.
        stripe_session = stripe.checkout.Session.retrieve(
            event['data']['object']['id'],
            expand=['line_items'],
        )
        fulfill_order(stripe_session)
    else:
        # Unexpected event type
        print('Unhandled event type {}'.format(event['type']))

    return {}, 200


def fulfill_order(stripe_session, status='Paid'):
    session_id = stripe_session['id']
    invoice_id = secrets.token_hex(16)
    shipping = stripe_session['shipping_cost']['amount_total'] // 100
    total = stripe_session['amount_total'] // 100
    detail = json.loads(stripe_session['metadata']['cart'])
    user_id = int(stripe_session['metadata']['user_id'])
    full_name = stripe_session['shipping_details']['name']
    address = stripe_session['shipping_details']['address']
    order = Order(
        session_id=session_id,
        invoice_id=invoice_id,
        status=status,
        shipping=shipping,
        total=total,
        detail=detail,
        user_id=user_id,
        full_name=full_name,
        address=address,
    )
    db.session.add(order)
    db.session.commit()


@app.route('/success')
def success():
    session_id = request.args.get('id')
    if not session_id:
        return redirect(url_for('index'))

    order = Order.query.filter_by(session_id=session_id).first_or_404()
    return render_template('success.html', session_id=order.session_id)


@app.route('/order')
@login_required
def order():
    orders = current_user.orders.order_by(Order.created_at.desc())
    return render_template('order.html', orders=orders)


@app.route('/order/detail/<string:session_id>')
@login_required
def order_detail(session_id):
    order = current_user.orders.filter_by(session_id=session_id).first_or_404()
    return render_template('order_detail.html', order=order)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data,
        )
        db.session.add(user)
        db.session.commit()
        flash('Thanks for registration!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password_correction(
            attempted_password=form.password.data
        ):
            login_user(user)

            next = request.args.get('next')
            if next:
                return redirect(next)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password! Please try again.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/reset-password-request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = ResetPasswodRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        token = user.generate_reset_token()
        if user:
            flash(
                'You will soon receive an email allowing you to reset your password. '
                'Please make sure to check your spam and trash if you can\'t find the email.',
                'success',
            )
            send_email(
                subject='Password reset request',
                recipients=[user.email],
                template='reset_password_request_email',
                username=user.username,
                url=url_for('reset_password', token=token, _external=True),
            )
        return redirect(url_for('login'))

    return render_template('reset_password_request.html', form=form)


@app.route('/reset-password/<string:token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token!', 'danger')
        return redirect(url_for('reset_password_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = form.password.data
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form)


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html', error=error)
