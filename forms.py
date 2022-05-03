from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, DateField
from wtforms.validators import DataRequired

#Forms class
class loginForm(FlaskForm):
    user = StringField("Usuario", validators=[DataRequired()])
    password = PasswordField("Contraseña", validators=[DataRequired()])
    submit = SubmitField("Iniciar sesión")

class userForm(FlaskForm):
    name = StringField("Nombre", validators=[DataRequired()])
    lastName = StringField("Apellido")
    job = StringField("Puesto")
    user = StringField("Usuario", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Contraseña")
    add = SubmitField("Agregar Usuario")

class keyValidityForm(FlaskForm):
    validity = DateField("Fecha de vencimiento", format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField("Generar Llave")

class uploadDocumentForm(FlaskForm):
    name = StringField("Nombre", validators=[DataRequired()])
    validity = DateField("Fecha de vencimiento", format='%Y-%m-%d', validators=[DataRequired()])
    signers = StringField("Firmantes", validators=[DataRequired()])
    submit = SubmitField("Subir Documento")

class signDocumentForm(FlaskForm):
    password = PasswordField("Contraseña del usuario", validators=[DataRequired()])
    submit = SubmitField("Firmar documento")