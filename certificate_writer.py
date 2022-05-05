from fpdf import FPDF
from datetime import datetime

version = "2.1.0"
sign_algorithm = "ECDSA de 256 bits con sha512"


def write_public_key_certificate(title,
id_certificate,
id_key,
number_of_key_recieved,
editor,
date_of_creation,
date_downloaded,
validity,
name_user,
user,
public_key,
save_directory):

    pdf = FPDF()
    pdf.add_page()
    
    #Set font for title
    pdf.set_font("Times", size = 22, style="B")
    
    # write title
    pdf.cell(200, 10, txt = title,
             ln = 1, align = 'C')

    #Set font for body 
    pdf.set_font("Times", size = 12)
    # Write certificate info
    pdf.cell(200, 20, txt = "Certificado generado el {}".format(datetime.now().strftime("%d/%m/%Y - %H:%M:%S")),
             ln = 2, align = 'c', )
    pdf.cell(200, 10, txt = "Versión del programa: " + version,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Algoritmo de firmado: " + sign_algorithm,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Id del certificado: " + id_certificate,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Id de la llave: " + id_key,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Número de llave generada: " + number_of_key_recieved,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Nomrbe del usuario: " + name_user,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Usuario: " + user,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Nombre del editor: " + editor,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Puesto del editor: admin",
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Fecha de creación de firma: " + date_of_creation,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Fecha de descargado de firma: " + date_downloaded,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Fecha de vencimiento de la firma: " + validity,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Llave pública generada: " + public_key.split(",")[0] + ",",
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = public_key.split(",")[1],
             ln = 2, align = 'L', )

    # save the pdf with name .pdf
    pdf.output(save_directory)
    
def write_sign_document_certificate(title,
id_certificate,
id_sign,
document_name,
date_of_signing,
validity_of_document,
name_signer,
user_signer,
job_signer,
public_key_signer,
save_directory):

    pdf = FPDF()
    pdf.add_page()
    
    #Set font for title
    pdf.set_font("Times", size = 22, style="B")
    
    # write title
    pdf.cell(200, 10, txt = title, 
             ln = 1, align = 'C')

    #Set font for body 
    pdf.set_font("Times", size = 12)
    # Write certificate info
    pdf.cell(200, 20, txt = "Certificado generado el {}".format(datetime.now().strftime("%d/%m/%Y - %H:%M:%S")),
             ln = 2, align = 'c', )
    pdf.cell(200, 10, txt = "Versión del programa: " + version,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Algoritmo de firmado: " + sign_algorithm,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Id del certificado: " + id_certificate,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Id de la firma utilizada: " + id_sign,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Nombre del firmante: " + name_signer,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Usuario del firmante: " + user_signer,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Puesto del firmante: " + job_signer,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Llave pública utilizada: " + public_key_signer.split(",")[0] + ",",
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = public_key_signer.split(",")[1],
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Nombre del documento firmado: " + document_name,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Fecha de firmado del documento: " + date_of_signing,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Fecha de vencimiento del documento firmado: " + validity_of_document,
             ln = 2, align = 'L', )

    # save the pdf with name .pdf
    pdf.output(save_directory)

def write_verification_sign_certificate(title,
id_certificate,
id_sign,
signing_key,
document_name,
verificator_name,
verificator_job,
validity_of_document,
name_signer,
user_signer,
job_signer,
public_key_signer,
save_directory):

    pdf = FPDF()
    pdf.add_page()
    
    #Set font for title
    pdf.set_font("Times", size = 22, style="B")
    
    # write title
    pdf.cell(200, 10, txt = title, 
             ln = 1, align = 'C')

    #Set font for body 
    pdf.set_font("Times", size = 12)
    # Write certificate info
    pdf.cell(200, 20, txt = "Certificado generado el {}".format(datetime.now().strftime("%d/%m/%Y - %H:%M:%S")),
             ln = 2, align = 'c', )
    pdf.cell(200, 10, txt = "Versión del programa: " + version,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Algoritmo de firmado: " + sign_algorithm,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Id del certificado: " + id_certificate,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Id de la firma: " + id_sign,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Clave de firma: " + signing_key,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Nombre del firmante: " + name_signer,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Usuario del firmante: " + user_signer,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Puesto del firmante: " + job_signer,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Nombre del documento firmado: " + document_name,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Nombre del verificador de firma: " + verificator_name,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Puesto del verificador de firma: " + verificator_job,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Fecha de vencimiento del documento" + validity_of_document,
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = "Llave pública con la que se firmó: " + public_key_signer.split(",")[0] + ",",
             ln = 2, align = 'L', )
    pdf.cell(200, 10, txt = public_key_signer.split(",")[1],
             ln = 2, align = 'L', )
    # save the pdf with name .pdf
    pdf.output(save_directory)