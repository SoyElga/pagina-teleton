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
