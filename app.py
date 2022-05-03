from ast import Pass
from cgi import print_environ_usage
from email.policy import default
from enum import unique
from importlib.resources import files
from logging.config import valid_ident
#from selectors import EpollSelector
import sqlite3
from unicodedata import name
from flask import Flask, redirect, url_for, render_template, flash, request, send_file
#from flask_wtf import FlaskForm
from sqlalchemy import nullslast
#from wtforms import StringField, SubmitField, PasswordField, DateField
#from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from cryptography import *
from hashlib import sha512
import hashlib
import os

#SQL
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime, timedelta

#Key generation
from curve_data import P_256
from readWrite import  write_private_key, private_key_read, sig_write, sig_read
from ECDSA_keyGenerator import *
from signVerify import *
from forms import *
from certificate_writer import *

app = Flask(__name__)
#Old SQLite DB
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

#New MySQL DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:1234@localhost/users'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#Secret Key
app.config['SECRET_KEY'] = "this is my secret key"
app.config['UPLOAD_FOLDER'] = "static/pdfs"

db = SQLAlchemy(app)
migrate = Migrate(app, db)

#Flask Login Stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

#Custom filters for jinja2
def shortName(name, l):
    if len(name) > l:
        return name[0:l]+"..."
    else:
        return name

def isDate(date):
    return date.strftime("%d/%m/%Y")

app.jinja_env.filters["short_name"] = shortName
app.jinja_env.filters["is_date"] = isDate

#Database user models
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100), nullable = False)
    lastname = db.Column(db.String(100))
    job = db.Column(db.String(100))
    user = db.Column(db.String(100), nullable = False, unique = True)
    email = db.Column(db.String(100), unique = True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    
    #Password
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError ('Password is not a readable attribute!')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    #Create a String
    def __repr__(self):
        return '<User %r>' % self.user

#Database keys model
class Keys(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    user = db.Column(db.String(100), nullable = False, unique = True)
    id_user = db.Column(db.Integer)
    public_key = db.Column(db.String(200), unique = True)
    private_key_hash = db.Column(db.String(128))
    validity = db.Column(db.DateTime, nullable=False)
    downloaded = db.Column(db.Boolean, default=False)
    number_generated_key = db.Column(db.Integer, default=1)
    date_modified = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.user

#Database signatures model
class Signatures(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100), nullable=False)
    id_file = db.Column(db.Integer, nullable=False)
    id_signer = db.Column(db.Integer, nullable=False)
    validity = db.Column(db.DateTime, nullable=False)
    fingerprint = db.Column(db.String(200), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    checked = db.Column(db.Boolean, default=False)
    signature_filename = db.Column(db.String(200), nullable=False, default="")

    def __repr__(self):
        return '<id firma: %r>' % self.id

class Files(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100), nullable=False)
    pdf_file = db.Column(db.String(200), nullable=False)
    all_signers = db.Column(db.String(200), nullable=False)
    validity = db.Column(db.DateTime, nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

class Certificates(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    display_for = db.Column(db.Integer, nullable=False) #Id de la persona a la que se le va a mostrar, para public key y signature es el usuario y para verification es el admin
    name = db.Column(db.String(200), nullable=False) # Nombre del certificado
    topic = db.Column(db.String(20), nullable=False) # El tema del certificado: clave publica, firma de documento o verificacion de firma
    pdf_directory = db.Column(db.String(200), nullable=False) # Directorio en el que se guarda el pdf del certificado
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

@app.route("/")
@app.route("/home")
@login_required
def index():
    try:
        os.remove("generated_keys/private.pem")
    except:
        print("No hay llave para borrar")
    
    keys = Keys.query.filter_by(id_user = current_user.id).first()
    signatures = Signatures.query.filter_by(id_signer = current_user.id).all()
    certificates = Certificates.query.filter_by(display_for = current_user.id).all()

    if len(signatures) >= 4:
        signatures = signatures[0:4]

    return render_template("index.html", keys = keys, now = datetime.now(), signatures=signatures, certificates=certificates)

@app.route("/login", methods=["GET","POST"])
def login():
    form = loginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(user=form.user.data).first()

        if user:
            #Check the hash
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                if user.id == 7:
                    return redirect(url_for('admin_index'))
                else:
                    return redirect(url_for('index'))

            else:
                flash("Contraseña incorrecta, vuelva a intentar")
        else:
            flash("Usuario no encontrado, vuelva a intentar")
        
        form.user.data = ""
        form.password.data = ""
    
    return render_template("login.html", 
    form = form)

@app.route("/logout", methods=["GET","POST"])
@login_required
def logout():
    logout_user()
    flash("Se ha salido de la sesión")
    return redirect(url_for('login'))

@app.route("/history")
@login_required
def history():
    return render_template("history.html")

@app.route("/certificates")
@login_required
def certificates():
    return render_template("certificates.html")

@app.route("/sign")
@login_required
def sign():
    signatures = Signatures.query.filter_by(id_signer=current_user.id).all()
    unsigned_signatures = [s for s in signatures if s.fingerprint == ""]
    return render_template("sign.html", signatures=unsigned_signatures, now = datetime.now())

@app.route("/sign/document/<int:id>", methods=["GET","POST"])
@login_required
def sign_document(id):
    form = signDocumentForm()
    signature = Signatures.query.filter_by(id = id).first()
    file_db = Files.query.filter_by(id = signature.id_file).first()
    key = Keys.query.filter_by(id_user=signature.id_signer).first()

    if request.method == "POST":
        user = Users.query.filter_by(id=signature.id_signer).first()
        if check_password_hash(current_user.password_hash, request.form["password"]):
            try:
                file = request.files["file"]
                filename = file.filename
                upload_folder = 'uploaded_key_for_signature'
                file.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),upload_folder,secure_filename(file.filename)))
                private_key_uploaded = private_key_read('uploaded_key_for_signature/'+filename)
                os.remove('uploaded_key_for_signature/'+filename)
                private_key_uploaded_hash = sha512(str(hex(private_key_uploaded)).encode()).hexdigest()

                # Checamos que la clave privada sea la misma que la registrada en la base de datos
                if private_key_uploaded_hash == key.private_key_hash:
                    rs, fingerprint = sign_doc(private_key_uploaded, P_256(), file_db.pdf_file)
                    try:
                        sig_write(rs, "signature_files/"+signature.name+"_"+user.user+"_")
                        signature.fingerprint = fingerprint
                        signature.signature_filename = signature.name+"_"+user.user+"_"+"signature.pem"
                        #dir_certificate = os.path.join(os.path.abspath(os.path.dirname(__file__)),"certificates","signature",
                        #                                secure_filename("{name_document}_{user}_signature_certificate.pdf".format(name_document=file_db.name.replace(" ", "_"), user=current_user.user)))
                        #certificate = Certificates(display_for = user.id,
                        #                           name = "Certificado firma de documento: {}".format(file_db.name),
                        #                           topic = "signature",
                        #                           pdf_directory = dir_certificate)
                        #db.session.add(certificate)
                        db.session.commit()
                        #write_sign_document_certificate(title = "Certificado de firma de documento",
                        #                                id_certificate = str(certificate.id),
                        #                                id_sign = str(signature.id),
                        #                                document_name = file_db.name,
                        #                                date_of_signing = datetime.now().strftime("%m/%d/%Y - %H:%M:%S"),
                        #                                validity_of_document = file_db.validity.strftime("%m/%d/%Y - %H:%M:%S"),
                        #                                name_signer = user.name + " " + user.lastname,
                        #                                user_signer = user.user,
                        #                                job_signer = user.job,
                        #                                public_key_signer = key.public_key,
                        #                                save_directory = dir_certificate)
                        
                        return redirect(url_for('sign'))
                    except:
                        flash("Hubo un error al subir la firma a la base de datos")
                        return render_template("sign_document.html", signature=signature, file=file_db,key=key, form=form, now=datetime.now())
                else:
                    flash("La clave privada no coincide con la de la base de datos")
                    return render_template("sign_document.html", signature=signature, file=file_db,key=key, form=form, now=datetime.now())
            except:
                flash("Hubo un error, vuelve a intentar")
                return render_template("sign_document.html", signature=signature, file=file_db,key=key, form=form, now=datetime.now())
        else:
            flash("La contraseña es incorrecta")
            return render_template("sign_document.html", signature=signature, file=file_db,key=key, form=form, now=datetime.now())

    return render_template("sign_document.html", signature=signature, file=file_db,key=key, form=form, now=datetime.now())

#Key Generator
def generate_key():
    '''Genera instancia de clave privada y publica'''
    curve=P_256()
    private_key = secure_random(curve.n)
    publicKey = public_key(curve,private_key)
    return (private_key,publicKey.Q)

@app.route("/get_keys/<int:id>")
@login_required
def get_keys(id):
    admin = Users.query.filter_by(id = 7).first()
    key_db = Keys.query.filter_by(id_user = id).first()
    private_key, public_key = generate_key()
    hex_public_key = ','.join([str(hex(p)) for p in public_key])
    private_key_hash = sha512(str(hex(private_key)).encode()).hexdigest()

    key_db.public_key = hex_public_key
    key_db.private_key_hash = private_key_hash
    key_db.downloaded = True

    #Datos certificado
    dir_certificate = os.path.join(os.path.abspath(os.path.dirname(__file__)),"certificates","public_key",secure_filename("{user}_private_key_certificate.pdf".format(user=current_user.user)))

    try:
        certificate = Certificates(display_for = current_user.id,
                               name = "Certificado Llave Pública #{}".format(key_db.number_generated_key),
                               topic = "public key",
                               pdf_directory = dir_certificate)
        db.session.add(certificate)
        db.session.commit()
        write_public_key_certificate(title = "Certificado de Llave pública",
                                    id_certificate = str(certificate.id),
                                    id_key = str(key_db.id),
                                    number_of_key_recieved = str(key_db.number_generated_key),
                                    editor = admin.name,
                                    date_of_creation = key_db.date_modified.strftime("%m/%d/%Y - %H:%M:%S"),
                                    date_downloaded = datetime.now().strftime("%m/%d/%Y - %H:%M:%S"),
                                    validity = key_db.validity.strftime("%m/%d/%Y - %H:%M:%S"),
                                    name_user = current_user.name + " " + current_user.lastname,
                                    user = current_user.user,
                                    public_key = hex_public_key,
                                    save_directory = dir_certificate
                                    )

        write_private_key(private_key, "generated_keys/private.pem")
        flash("Se ha descargado correctamente la firma")
        return send_file('generated_keys/private.pem', as_attachment=True)
    except Exception as e:
        flash("Hubo un error al descargar las firmas")
        print(e)
        return redirect(url_for("index"))

#Paginas de admin
@app.route("/admin/home")
@login_required
def admin_index():
    if not current_user.id == 7:
        #No eres el admin
        flash("Debes ser admin para tener acceso a esa página")
        return redirect(url_for("index"))
    else:
        return render_template("index_admin.html")

@app.route("/admin/users")
@login_required
def list_users():
    if not current_user.id == 7:
        #No eres el admin
        flash("Debes ser admin para tener acceso a esa página")
        return redirect(url_for("index"))
    else:
        users = Users.query.order_by(Users.id)
        keys = Keys.query.order_by(Keys.id_user)

        our_users = {}
        for j,user in enumerate(users):
            our_users[j] = {"user": user, 'key':''}

        for j, key in enumerate(keys):
            our_users[j]["key"] = key

        now = datetime.now()

        return render_template("list_users.html", our_users=our_users, now=now)

@app.route("/admin/users/add", methods=["GET","POST"])
@login_required
def add_user():
    if not current_user.id == 7:
        #No eres el admin
        flash("Debes ser admin para tener acceso a esa página")
        return redirect(url_for("index"))
    else:
        form = userForm()

        def clean_form():
            form.name.data = ''
            form.lastName.data = ''
            form.job.data = ''
            form.user.data = ''
            form.email.data = ''
            form.password.data = ''

        if form.validate_on_submit():
            user = Users.query.filter_by(user = form.user.data).first()
            if user is None:
                #hash the password
                hashed_pw = generate_password_hash(form.password.data, "sha256")
                user = Users(name=form.name.data, 
                            lastname = form.lastName.data,
                            job = form.job.data,
                            user = form.user.data,
                            email = form.email.data,
                            password_hash=hashed_pw)
                db.session.add(user)
                db.session.commit()

                registered_key = Keys(
                    user = user.user,
                    id_user = user.id,
                    public_key = None,
                    private_key_hash = None,
                    validity = datetime.now() - timedelta(days=1), 
                    date_modified = datetime.now()
                )
                db.session.add(registered_key)
                db.session.commit()

                flash("El usuario se ha agregado con éxito")
                clean_form()
                return redirect(url_for('list_users'))
            else:
                flash("El usuario ya existe")
                clean_form()
        else:
            flash("No se ha podido agregar al usuario")

        return render_template("add_user.html", 
        form = form)

@app.route("/admin/users/update/<int:id>", methods=["GET","POST"])
@login_required
def update_user(id):
    if not current_user.id == 7:
        #No eres el admin
        flash("Debes ser admin para tener acceso a esa página")
        return redirect(url_for("index"))
    else:
        form = userForm()
        user_to_update = Users.query.get_or_404(id)

        if request.method == "POST":
            user_to_update.name = request.form["name"]
            user_to_update.lastName = request.form["lastName"]
            user_to_update.job = request.form["job"]
            user_to_update.user = request.form["user"]
            user_to_update.email = request.form["email"]
            try:
                db.session.commit()
                flash("Usuario actualizado correctamente!")
                return redirect(url_for("list_users"))
            except:
                flash("Hubo un error al actualizar el usuario")
                return render_template("update_user.html", form=form, user_to_update=user_to_update)
        else:
            return render_template("update_user.html", form=form, user_to_update=user_to_update)

@app.route("/admin/users/delete/<int:id>")
@login_required
def delete_user(id):
    if not current_user.id == 7:
        #No eres el admin
        flash("Debes ser admin para tener acceso a esa página")
        return redirect(url_for("index"))
    else:
        user_to_delete = Users.query.get_or_404(id)
        key_to_delete = Keys.query.filter_by(id_user = id).first()
        all_signatures = Signatures.query.filter_by(id_signer = id).all()

        try:
            #Borramos todas las firmas que esten a su nombre
            for signature in all_signatures:
                db.session.delete(signature)
            #Borramos al usuario y sus llaves
            db.session.delete(user_to_delete)
            db.session.delete(key_to_delete)
            db.session.commit()
            flash("Usuario borrado con éxito")
            return redirect(url_for("list_users"))
        except:
            flash("Hubo un error al borrar al ususario", user_to_delete.user)
            return redirect(url_for("update_user", id=id))

@app.route("/admin/users/generate_keys/<int:id>", methods=["GET", "POST"])
@login_required
def generate_user_key(id):
    if not current_user.id == 7:
        #No eres el admin
        flash("Debes ser admin para tener acceso a esa página")
        return redirect(url_for("index"))
    else:
        form = keyValidityForm()
        user_to_generate_key = Users.query.get_or_404(id)
        registered_key = Keys.query.filter_by(id_user = user_to_generate_key.id).first()
        if form.validate_on_submit():
            registered_key.validity = form.validity.data
            registered_key.downloaded = False
            registered_key.number_generated_key += 1
            registered_key.date_modified = datetime.now()
            try:
                db.session.commit()
                flash("Fecha de validez de la firma actualizada")
                return redirect(url_for('list_users'))
            except:
                flash("Hubo un error al actualizar la fecha de validez")
                return render_template("validity_key_generation.html", form=form, user=user_to_generate_key)
        return render_template("validity_key_generation.html", form=form, user=user_to_generate_key, key = registered_key)

@app.route("/admin/upload_document", methods=["GET","POST"])
@login_required
def upload_document():
    if not current_user.id == 7:
        #No eres el admin
        flash("Debes ser admin para tener acceso a esa página")
        return redirect(url_for("index"))
    else:
        users = Users.query.order_by(Users.date_added).all()
        form = uploadDocumentForm()
        #Quitamos al admin de los firmantes
        admin = 0
        for i, user in enumerate(users):
            if user.user == "admin":
                admin = i
                break
        users.pop(admin)

        usernames_in_db = [u.user for u in users]
        if request.method == "POST":
            users_to_sign = request.form['signers'].split(", ")
            #Quitamos los duplicados con el fromkeys y checamos que todos los usuarios escritos esten en la base de datos, de no ser asi mandamos mensaje de error
            users_to_sign_in_db = list(dict.fromkeys([u for u in users_to_sign if u in usernames_in_db]))
            if users_to_sign_in_db == users_to_sign:
                file = request.files["file"]
                if file.filename == "":
                    flash("No se ha seleccionado un archivo para subir")
                    return render_template("upload_document.html", users=users, form=form)
                elif not file.filename.split(".")[-1] == "pdf":
                    flash("El archivo que se suba debe tener la extension .pdf")
                    return render_template("upload_document.html", users=users, form=form)
                else:
                    directory_route = os.path.join(os.path.abspath(os.path.dirname(__file__)),app.config["UPLOAD_FOLDER"],secure_filename(file.filename)) 
                    file.save(directory_route)
                    #Conseguimos las ids de los usuarios y lo convertimos en un string que separa las ids con una coma y un espacio
                    ids_signers_str = ", ".join([str(user.id) for user in users if user.user in users_to_sign_in_db])

                    file_db = Files(
                        pdf_file = directory_route,
                        name = request.form["name"],
                        all_signers = ids_signers_str,
                        validity = request.form["validity"]
                    )
                    db.session.add(file_db)
                    db.session.commit()

                    for id_user in ids_signers_str.split(", "):
                        #EL id_user es un str, entonces primero tenemos que convertirlo a int
                        id_int = int(id_user)
                        signature = Signatures(
                            name = request.form['name'],
                            id_file = file_db.id,
                            id_signer = id_int,
                            validity = request.form["validity"],
                            fingerprint = ""
                        )
                        db.session.add(signature)
                        db.session.commit()
                    flash("Se ha subido correctamente el documento")
                    return render_template("upload_document.html", users=users, form=form)
            else:
                flash("Asegurate que los firmantes sean válidos")
                return render_template("upload_document.html", users=users, form=form)

        return render_template("upload_document.html", users=users, form=form)

@app.route("/admin/documents")
@login_required
def documents():
    if not current_user.id == 7:
        #No eres el admin
        flash("Debes ser admin para tener acceso a esa página")
        return redirect(url_for("index"))
    else:
        db_files = Files.query.order_by(Files.date_added).all()
        db_signatures = Signatures.query.order_by(Signatures.date_added).all()
        files = {}
        for i,file in enumerate(db_files):
            signatures = [s.id for s in db_signatures if s.id_file == file.id and s.checked]
            files[i] = {"Name":file.name, "Date_added":file.date_added.strftime("%d/%m/%Y"), "File_id":file.id, "Validity":file.validity, "Valid_signatures":len(signatures), "Total_signatures":len(file.all_signers.split(", "))}
        return render_template('documents.html', files = files, now = datetime.now())

@app.route("/admin/documents/document/<int:id>")
@login_required
def document(id):
    if not current_user.id == 7:
        #No eres el admin
        flash("Debes ser admin para tener acceso a esa página")
        return redirect(url_for("index"))
    else:
        file = Files.query.filter_by(id = id).first()
        signatures = Signatures.query.filter_by(id_file = id).all()
        users = []
        for id_user in [s.id_signer for s in signatures]:
            users.append(Users.query.filter_by(id=id_user).first())

        signers = {}
        for i,user in enumerate(users):
            user_signature = [s.id for s in signatures if s.id_signer == user.id]
            signers[i] = {"name":user.name + " " + user.lastname, "username":user.user, "fingerprint": signatures[i].fingerprint, "sign_checked":signatures[i].checked, "id_signature":user_signature[0]}

        for non_user in range(len(file.all_signers.split(", ")) - len(users)):
            signers[len(signers)] = "Usuario Borrado"

        return render_template("document.html", file=file, signers=signers)

@app.route("/documents/document/download/<int:id>")
@login_required
def download_document(id):
    file = Files.query.filter_by(id = id).first()
    try:
        flash("Se ha descargado correctamente el documento")
        return send_file(file.pdf_file, as_attachment=True)
    except:
        flash("Hubo un error con la descarga del documento")
        return redirect(url_for("document", id=id))

def public_key_read(public_key_str) -> 'tuple(int,int)':
    numbers = public_key_str.split(",")
    return (int(numbers[0],base=16),int(numbers[1],base=16))

@app.route("/admin/documents/document/verify_signature/<int:id>")
@login_required
def verify_signature(id):
    if not current_user.id == 7:
        #No eres el admin
        flash("Debes ser admin para tener acceso a esa página")
        return redirect(url_for("index"))
    else:
        signature = Signatures.query.filter_by(id=id).first()
        key = Keys.query.filter_by(id_user=signature.id_signer).first()
        file = Files.query.filter_by(id=signature.id_file).first()
        signer = Users.query.filter_by(id=signature.id_signer).first()

        signature_tuple = sig_read("signature_files/"+signature.signature_filename)
        loaded_public_key = public_key_read(key.public_key)
        
        PK_curve_form=P_256()
        PK_curve_form.Q=loaded_public_key
        if verify(signature_tuple,P_256(),PK_curve_form,file.pdf_file):
            signature.checked = True
            #signer = Users.query.filter_by(id = signature.id_signer).first()
            #dir_certificate = os.path.join(os.path.abspath(os.path.dirname(__file__)),"certificates","verification",secure_filename("{document_name}_{signer}_verification_certificate.pdf".format(document_name=file.name.replace(" ", "_").id, signer=signer.user)))
            #certificate = Certificates(display_for = current_user.id,
            #                            name = "Certificado Verificación: {}".format(file.name),
            #                            topic = "verification",
            #                            pdf_directory = dir_certificate)
            #db.session.add(certificate)
            db.session.commit()
            #write_verification_sign_certificate(title = "Certificado de verificación de firma",
            #                                    id_certificate = str(certificate.id),
            #                                    id_sign = str(signature.id),
            #                                    signing_key = str(hex(signature_tuple[0])) + ", " + str(hex(signature_tuple[1])),
            #                                    document_name = file.name,
            #                                    verificator_name = current_user.name + " " + current_user.lastname,
            #                                    verificator_job = current_user.job,
            #                                    validity_of_document = file.validity.strftime("%m/%d/%Y - %H:%M:%S"),
            #                                    name_signer = signer.name + " " + signer.lastname,
            #                                    user_signer = signer.user,
            #                                    job_signer = signer.job,
            #                                    public_key_signer = key.public_key,
            #                                    save_directory = dir_certificate)
            flash("Se ha verificado la firma con exito")

            #return send_file(dir_certificate, as_attachment=True)
            return redirect(url_for("document",id=signature.id_file))
        else:
            flash("No se ha podido verificar la firma")
            return redirect(url_for("document",id=signature.id_file))
        
@app.route("/admin/documents/document/delete_document/<int:id>")
@login_required
def delete_document(id):
    if not current_user.id == 7:
        #No eres el admin
        flash("Debes ser admin para tener acceso a esa página")
        return redirect(url_for("index"))
    else:
        file = Files.query.filter_by(id=id).first()
        signatures = Signatures.query.filter_by(id_file=id).all()

        try:
            os.remove(file.pdf_file)
            db.session.delete(file)
            for s in signatures:
                db.session.delete(s)
            db.session.commit()
            flash("Documento y solicitudes de firma borrados con éxito")
            return redirect(url_for("documents"))
        except:
            flash("Hubo un error al borrar el documento")
            return redirect(url_for("document", id=id))


if __name__ == "__main__":
    app.run()