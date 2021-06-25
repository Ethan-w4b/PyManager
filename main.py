# plan
# requirements - sql to store passwords/usernames/emails
import os
import json
import hashlib
import sqlite3 as sql
from cryptography.fernet import Fernet

logins = {}

con = sql.connect(r'pythonSQL.db')
cur = con.cursor()



#cur.execute("CREATE TABLE accounts (site TEXT, email TEXT, passw INTEGER)")
#cur.execute("INSERT INTO accounts VALUES ('amazon', 'bobe@lost.net', 1234)")
#con.commit()
#cur.execute("INSERT INTO accounts VALUES ('youtube', 'bobe@lost.net', 347)")
#rows = cur.execute("SELECT site, email, passw FROM accounts").fetchall()

def help():
    print('')

def view_accounts():
    sites = cur.execute("SELECT site FROM accounts").fetchall()
    email = cur.execute("SELECT email FROM accounts").fetchall()
    passw = cur.execute("SELECT passw FROM accounts").fetchall()


    '''for row in cur.execute("PRAGMA table_info('accounts')").fetchall():
        table_data.append(row[1])'''

    table_row1 = '| SITE | EMAIL | PASSWORD |\n'

    cnt = 0
    for i in range(len(sites)):
        table_row1 = table_row1 + f'| {sites[cnt]} | {email[cnt]} | ***** |\n'
        cnt += 1
    print(table_row1)


def select_account():
    selection = input("Enter site..")
    row = cur.execute("SELECT site, email, passw FROM accounts WHERE site = ?", (selection,)).fetchall()
    if row == []:
        print("Could not find account.")
    else:
        print(row)

        a = input('Reveal password? y/n')
        if a == 'y':
            password = row[0][2]
            print(decrypt_pswd(password))


def add_account():
    a_site = input("Enter website name: ")
    my_email = input("Enter username/email: ")
    pswd = input('Enter password: ')

    # encryption
    pswd = encrypt_pswd(pswd)

    cur.execute("INSERT INTO accounts (site, email, passw) VALUES (?, ?, ?)", (a_site, my_email, pswd))
    con.commit()
    rows = cur.execute("SELECT site, email, passw FROM accounts").fetchall()
    print('Added: ', rows)


def delete_account():
    a_site = input('Enter website of account you want deleted')
    cur.execute("DELETE FROM accounts WHERE site = ?", (a_site,))
    con.commit()
    print('Account deleted')


def quit():
    print('Closing PyManager')
    global running
    running = False
    cur.close()
    con.close()

# commands
command_index = {'!add': add_account, '!select': select_account, '!view': view_accounts, '!delete': delete_account,'!quit': quit}


# main loop functions
def trigger(func):
    func()


# crypto section
def gen_key():
    if os.path.exists("secret.key") == False:
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    else:
        pass

def load_key():
    return open("secret.key","rb").read()


def encrypt_pswd(paswd):
    key = load_key()
    F = Fernet(key)
    encrypted_pswd = F.encrypt(paswd.encode())

    return encrypted_pswd


def decrypt_pswd(paswd):
    key = load_key()
    F = Fernet(key)
    decrypted_paswd = F.decrypt(paswd)

    return decrypted_paswd.decode()


def login():
    # new login can be created only if login.json is empty. if removed it can't overwrite the hashed password stored in msecret.txt
    with open('login.json', 'r') as read_login:
        data = json.load(read_login)



    # check if login password has been created
    if data == {}:
        salt = os.urandom(32)
        new_username = input('<PyManager>\nCreate username: ')
        m_password = input('<PyManager>\nCreate a password for your login: ')
        hash_key = hashlib.pbkdf2_hmac('sha256', m_password.encode('utf-8'), salt, 100000)
        w_storage = salt + hash_key

        with open('msecret.txt', 'wb') as master_file:
            master_file.write(w_storage)

        new_user = {new_username: 'msecret.txt'}
        # saving login data
        with open('login.json', 'w') as login_file:
            json.dump(new_user, login_file)

        # read stored hash and compare to inputed password
        username_to_check = input('<PyManager>\n Username: ')
        password_to_check = input('<PyManager>\n Password: ')

        with open('msecret.txt', 'rb') as read_file:
            r_storage = read_file.read()

        salt_from_storage = r_storage[:32]
        key_from_storage = r_storage[32:]

        new_key = hashlib.pbkdf2_hmac('sha256', password_to_check.encode('utf-8'), salt_from_storage, 100000)

    else:
        # read stored hash and compare to inputed password
        with open('msecret.txt', 'rb') as read_file:
            r_storage = read_file.read()

        with open('login.json', 'r') as read_login:
            login_data = json.load(read_login)

        salt_from_storage = r_storage[:32]
        key_from_storage = r_storage[32:]
        username_to_check = input('<PyManager>\nUsername: ')
        password_to_check = input('Password: ')
        
        new_key = hashlib.pbkdf2_hmac('sha256', password_to_check.encode('utf-8'), salt_from_storage, 100000)

    if username_to_check not in login_data:
        print('Username not found')
        login()

    elif new_key == key_from_storage:
        print('Welcome')
    else:
        print('password incorrect')
        login()

def main():
    login()
    gen_key()
    global running
    running = True
    print('<PyManager>')
    print('Commands ...\n'
          '!add, !select, !delete, !view, !quit\n')
    while running:
        _input = input('<PyManager>')
        try:
            trigger(command_index[_input])
        except KeyError:
            print('Command not recognized')

        if running == False:
            break


if __name__ == '__main__':
    main()
