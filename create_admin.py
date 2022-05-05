from app import Users, db, generate_password_hash, os

admin = Users.query.filter_by(user="admin").first()
if admin == None:
    password = ("Ingresa la contraseña que se le va a dar al admin, esta puede ser cambiada después: ")
    hashed_pw = generate_password_hash("", "sha256")
    admin = Users(name="Admin's name", 
                lastname = "Admin's lastname",
                job = "admin",
                user = "admin",
                email = "Admin's email",
                password_hash=hashed_pw)
    db.session.add(admin)
    db.session.commit()

    with open("basic_info.py", "w") as p:
        p.write("secret_key = 'this is my secret key'")
        p.write("admin_id = {}".format(admin.id))
    
else:
    delete_admin = ""
    while not delete_admin == "Y" or not delete_admin == "n":
        delete_admin = input("Ya existe un admin en la base de datos, ¿deseas borrar este usuario? Y/n")
        if not delete_admin == "Y" or not delete_admin == "n":
            print("Esa no es una respuesta válida")
    if delete_admin == "Y":
        try:
            db.session.delete(admin)
            db.session.commit()
        except Exception as e:
            print("Hubo un error:",e)
            print("Vuelva a intentarlo")


"""
Una vez agregado el usuario de admin y viendo que este funciona se puede borrar este script
"""
