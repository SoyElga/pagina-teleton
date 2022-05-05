# Sistema de firma digital
* Este sistema se usa para firmar y verificar documentos usando criptografia de clave publica 
* El archivo keyGenerator.py se usa para generar los pares de clave pública y clave privada de una entidad autorizada
* El archivo de clave privada se usa para firmar el archivo, por su parte el de clave pública se usa para verificar
que la firma es válida. Estos archivos se codifican como archivos .pem
* El algoritmo usado para firmar es ECDSA: Elliptic Curve Digital Signature Algorithm, con función hash a elegir entre SHA1, SHA224 y SHA256
* El hash es generado a partir de la representacion en bytes del archivo a firmar
* Las firmas se generan en formato .pem
* Las dependencias están listadas en requirements.txt
* Las credenciales tienen una vigencia fijada por el administrador cuando crea el par de llaves
* Los documentos tienen una vigencia, la cual es la fecha límite de firma del mismo
* Las firmas tienen una vigencia hasta la vigencia del documento firmado

# ATENCION!!!
* Antes de correr la página es importante correr el código de create_admin, este creará el perfil de admin en la base de datos que se use si no existe en la tabla de Users, en el caso de que no exista creará el perfil y generará un código que va a guardar el id del admin y generará la contraseña que se usa para WTForms, esta contraseña se puede modificar ya dentro de la página 
