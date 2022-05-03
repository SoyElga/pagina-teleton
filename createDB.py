#Este código se usa para crear las bases de datos en MySQL
import mysql.connector

mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="1234"
)

my_cursor = mydb.cursor()

#my_cursor.execute("CREATE DATABASE users")

my_cursor.execute("SHOW DATABASES")
for db in my_cursor:
    print(db)