import functools
import os
from unittest import result
from werkzeug.security import generate_password_hash, check_password_hash
import yagmail as yagmail
from flask import Flask, render_template, flash, request, redirect, url_for, jsonify, g, session
from flask import make_response
import utils
from db import close_db, get_db
from formulario import Contactenos
from message import mensajes

app = Flask( __name__ )
app.secret_key = os.urandom( 24 )


@app.route( '/' )
def index():
    return render_template( 'login.html' )


@app.route( '/register', methods=('GET', 'POST') )
def register():
    try:
        if request.method == 'POST':
            
            name= request.form['nombre']
            username = request.form['username']
            password = request.form['password']
            email = request.form['correo']
            error = None
            db = get_db()

            if not utils.isUsernameValid( username ):
                error = "El usuario debe ser alfanumerico o incluir solo '.','_','-'"
                flash( error )
                return render_template( 'register.html' )

            if not utils.isPasswordValid( password ):
                error = 'La contraseña debe contenir al menos una minúscula, una mayúscula, un número, un caracter especial y 8 caracteres'
                flash( error )
                return render_template( 'register.html' )

            if not utils.isEmailValid( email ):
                error = 'Correo invalido'
                flash( error )
                return render_template( 'register.html' )

            if db.execute( 'SELECT * FROM usuario WHERE correo = ?', (email,) ).fetchone() is not None:
                error = 'El correo ya existe'.format( email )
                flash( error )
                return render_template( 'register.html' )
           
            db.executescript(
                "INSERT INTO usuario (nombre, usuario, correo, contraseña) VALUES ('%s','%s','%s','%s')" % (name, username, email, generate_password_hash(password))
            )
            db.commit()

            close_db()

            flash( 'Revisa tu correo para activar tu cuenta' )
            return redirect( 'login' )
        return render_template( 'register.html' )
    except:
        return render_template( 'register.html' )

@app.route('/base')
def base():
    return render_template('base.html')

@app.route('/send', methods=('GET','POST'))
def send():
    return render_template('send.html')

@app.route( '/login', methods=('GET', 'POST') )
def login():
    try:
        if request.method == 'POST':
            db = get_db()
            error = None
            username = request.form['username']
            password = request.form['password']

            if not username:
                error = 'Debes ingresar el usuario'
                flash( error )
                return render_template( 'login.html' )

            if not password:
                error = 'Contraseña requerida'
                flash( error )
                return render_template( 'login.html' )

            user = db.execute(
                'SELECT * FROM usuario WHERE usuario = ? AND contraseña = ? ', (username, password)
            ).fetchone()

            if user is None:
                user = db.execute( 'SELECT * FROM usuario WHERE usuario = ?', (username,) ).fetchone()
                if  user is None:
                    error = 'El usuario NO existe'
                    flash( error )
                    return render_template( 'register.html' )
                else:
                     store_password = user[4]
                     result = check_password_hash(store_password,password)
                     if  result is False:
                        error = 'La contraseña esta errada'
                        flash( error )
                        return render_template( 'register.html' )
                     else:
                        session.clear()
                        session['user_id']=user[0]
                        resp = make_response(redirect(url_for('send')))
                        resp.set_cookie('username', username)
                        return resp



            close_db()

            """
            if user is None:
                error = 'Usuario o contraseña inválidos'
            else:
                return redirect( 'message' )
            flash( error )"""
        return render_template( 'login.html' )
    except:
        return render_template( 'login.html' )


@app.route( '/contacto', methods=('GET', 'POST') )
def contacto():
    form = Contactenos()
    return render_template( 'contacto.html', titulo='Contactenos', form=form )


@app.route( '/message', methods=('GET', 'POST') )
def message():
    print( "Retrieving info" )
    return jsonify( {'mensajes': mensajes} )

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view


if __name__ == '__main__':
    app.run()
