import sqlite3, hashlib
from tkinter import *

#Database code
with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")

#Initiate Window
window = Tk()

window.title("Password Vault")

def hashPassword(input):
    hash = hashlib.md5(input)
    hash = hash.hexdigest()
    
    return hash

def firstScreen():
    window.geometry("350x150")
    
    lbl = Label(window, text="Create Master Password")
    lbl.config(anchor = CENTER)
    lbl.pack()
    
    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()
    
    lbl1 = Label(window, text="Re-enter Master Password")
    lbl1.pack()
    
    txt1 = Entry(window, width=20, show="*")
    txt1.pack()
    txt1.focus()
    
    lbl2 = Label(window)
    lbl2.pack()
    
    def savePassword():
        if txt.get() == txt1.get():
            hashedPasword = hashPassword(txt.get().encode('utf-8'))
            
            insert_password = """INSERT INTO masterpassword(password)
            VALUES(?)"""
            cursor.execute(insert_password, [(hashedPasword)])
            db.commit()
            
            passwordValut()
        else:
            lbl2.config(text="Passwords do not match!", fg="red")
    
    btn = Button(window, text="Save", command=savePassword)
    btn.pack(pady=5)

def loginScreen():
    window.geometry("250x100")
    
    lbl = Label(window, text="Enter Master Password")
    lbl.config(anchor = CENTER)
    lbl.pack()
    
    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()
    
    lbl1 = Label(window)
    lbl1.pack()
    
    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8')) 
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)])
        print(checkHashedPassword)
        return cursor.fetchall()
    
    def checkPassword():
        match = getMasterPassword()
        
        print(match)
        
        if match:
            passwordValut()
        else:
            txt.delete(0, END)
            lbl1.config(text="Wrong Password!", fg="red")
    
    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=10)
    
def passwordValut():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("700x350")
    
    lbl = Label(window, text="Password Vault")
    lbl.config(anchor = CENTER)
    lbl.pack()
    
cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()
window.mainloop()