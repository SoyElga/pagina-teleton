# 30 de marzo 2022
* Se modificó el archivo main.py para que la notacion de las firmas sea procesada en formato (r,s) de acuerdo a lo establecido por el NIST.
* Se corrigió el archivo requirements.txt, ahora no contiene referencias a path del sistema
* Se modificó el procesamiento de archivos de firma, ahora estos se generan en .PEM y son decodificados al momento de verificar firma
* Se quitaron importaciones reduntantes 
# 31 de marzo 20222
* Ahora los módulos de lectura, escritura, carga de firmas y verificación de firmas son independientes 
    * De esta manera el código es más legible y escalable 
* Se documentaron las funciones existentes y se agregó type hinting donde todavía no lo había 
# 7 de abril 2022
* El código fue totalmente re-estructurado, ya no se depende de la librería de cryptography para todo el proceso
* Las claves ahora son generadas con una implementación propia que considera timing attacks
    * La clave privada se genera usando el módulo secrets
    * La clave pública se genera usando la clase curves, y el algoritmo doubling and adding
    * Los hashes de los archivos ahora son calculados usando hashlib, se puede configurar la función hash deseada, 
    de momento solo se soportan SHA1, SHA224 y SHA256
* La implementación ha sido probada con los vectores de prueba proporcionados por el **RFC6979** usando la curva **NIST P-256**, ver modulo tests
# 9 de abril 2022
* Se agregó soporte para funciones hash SHA384 y SHA512
# 16 de abril de 2022
* Se corrigieron errores en la documentacion e implementacion de los metodos de escritura de clave publica y privada
* Se corrigió el banner de generación exitosa de par de claves 
* Se removieron importaciones innecesarias 
* Se agrego un sistema de base de datos que permite llevar registro de la vigencia de las credenciales de firma
* Se agrego un sistema de base de datos que permite llevar registro de la vigencia de las firmas. Cabe mencionar que una persona que en este momento no puede firmar puede tener firmas vigentes, es totalmente valido, mas no puede emitir nuevas firmas
# 17 de abril de 2022
* Hotfix en el sistema de busqueda de firmas, ahora se busca por fingerprint y por firmante en lugar de solo firmante
* Se corrigio el nombre de el campo Firmas.id_firmante por Firmas.idFirmante
# 19 de abril de 2022
* Se corrigió un error en el esquema de la base de datos. Claves.id fue reemplazado por Claves.idFirmante y Firmas.id por Firmas.idFirma
# 21 de abril de 2022
* Se empezó a desarrollar la pagína web de Flask, se crearon las plantillas principales y las que se iban a usar en un futuro
# 22 de abril de 2022
* Se creó la base de datos en SQLite, se creó la tabla de Usuarios en la base de datos y las funciones de agregar, modificar y eliminar usuario
# 23 de abril de 2022
* Se migró la base de datos de SQLite a mySql, se trabajó en los diseños de las plantillas
# 25 de abril de 2022
* Se creó la tabla de Keys
* Se modificó la función de agrear usuario para que tambien agregue el perfil de su llave a la nueva tabla
* Se movió las función de generate_keys del script de database_manager a la app, ya que no se iba a usar más el script de database_manager y todo se iba a modificar con SQLAlchemy
* Se agregó la función de descargar llave privada desde el inicio del usuario
# 28 de abril de 2022
* Se agregaron las tablas de Keys y Signatures a la base de datos
* Se agregó la función de subir documento
* Se agregó la posibilidad de multiples firmas en un mismo documento, usando las mismas funciones y tratando cada solicitud de firma como única
# 29 de abril de 2022
* Se agregó la visualización de los documentos a los perfiles de usuarios y una visión de todos los documentos al perfil de admin
# 30 de abril de 2022
* Se modificó la función de sign para que no tenga que checar la vigencia del archivo en la base de datos
* Se cambio el nombre de la función sign a sign_doc
* Se implementó la función de sign_doc a la página web
# 1 de mayo de 2022
* Se implementó la función de verify a la página web
* Se modificó la visualización de los documentos para que te enseñe en que parte del proceso de firmado y verifiación de firma se encuentra una solicitud de firma
# 2 de mayo de 2022
* Se creó la tabla de Certificates en la base de datos
* Se desarrollo el scirpt de certificate_writer para escribir los diferentes certificados en PDF
# 3 de mayo de 2022
* Se implementó la generación de certificados en los procesos de descarga de firmas, firmado de documento y verificación de firma
* Se desarrolló la visualización de la página de inicio del admin
* Se desarrolló la visualización de la página de certificados de los usuarios
* Se desarrolló la visualización de la página de historial de los usuarios
# 4 de mayo de 2022
* Se desarrolló el scipt de create_admin para agregar al usuario admin antes de correr la página y que se tenga acceso a las páginas del usuario admin