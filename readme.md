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
* Las firmas tienen una vigencia de 3 dias

