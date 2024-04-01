from threading import Thread

from flask import render_template
from flask_mail import Message

from . import app, mail


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(subject, recipients, template, **kwargs):
    msg = Message(subject=subject, recipients=recipients)
    msg.body = render_template(f'{template}.txt', **kwargs)
    msg.html = render_template(f'{template}.html', **kwargs)
    Thread(target=send_async_email, args=(app, msg)).start()
