import socket
import mysql.connector
import random
import string

HOST = '127.0.0.1'
PORT = 106

# MySQL configurations
MYSQL_HOST = ''
MYSQL_USER = ''
MYSQL_PASSWORD = ''
MYSQL_DB = ''
MYSQL_TABLE = ''


def connect_to_db():
    try:
        connection = mysql.connector.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DB
        )
        print("Connected to database successfully.")
        return connection
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return None


import crypt


def check_password(email, password):
    conn = connect_to_db()
    if not conn:
        return False

    try:
        cursor = conn.cursor(buffered=True)
        cursor.execute("SELECT password FROM {} WHERE email=%s".format(MYSQL_TABLE), (email,))
        stored_password = cursor.fetchone()
        if stored_password:
            # Extract the salt from the stored hash
            salt_parts = stored_password[0].split('$')
            if len(salt_parts) != 4:
                print(f"Unexpected hash format: {stored_password[0]}")
                return False

            salt = '$6$' + salt_parts[2] + '$'
            encrypted_input = crypt.crypt(password, salt)

            print(f"Encrypted provided password: {encrypted_input}")  # Debugging
            print(f"Stored password: {stored_password[0]}")  # Debugging

            if encrypted_input == stored_password[0]:
                return True

        return False

    except Exception as e:
        print(f"Error checking password: {e}")
        return False
    finally:
        conn.close()


def update_password(email, new_password):
    conn = connect_to_db()
    if not conn:
        return False

    try:
        salt = '$6$' + ''.join(random.choices(string.ascii_letters + string.digits, k=16)) + '$'
        encrypted_password = crypt.crypt(new_password, salt)

        cursor = conn.cursor(buffered=True)
        cursor.execute("UPDATE {} SET password=%s WHERE email=%s".format(MYSQL_TABLE), (encrypted_password, email))
        conn.commit()
        return cursor.rowcount > 0

    except Exception as e:
        print(f"Error updating password: {e}")
        return False
    finally:
        conn.close()


def handle_client(conn):
    try:
        conn.sendall(b'200 Hello, this is the fake poppassd\r\n')

        # User step
        data = conn.recv(1024)
        print(f"Received data (USER step): {data}")
        if not data.upper().startswith(b'USER'):
            conn.sendall(b'-ERR Expected USER command\r\n')
            return

        email = data.split()[1].decode('utf-8')
        print(f"Received email: {email}")
        conn.sendall(b'200 OK\r\n')

        # Old password step
        data = conn.recv(1024)
        print(f"Received data (OLDPASS step): {data}")
        if not data.upper().startswith(b'PASS'):
            conn.sendall(b'-ERR Expected OLDPASS command\r\n')
            return

        old_password = data.split()[1].decode('utf-8')
        print(f"Received old password: {old_password}")

        if not check_password(email, old_password):
            print("Old password does not match database record.")
            conn.sendall(b'-ERR Incorrect old password\r\n')
            return

        conn.sendall(b'200 OK\r\n')

        # New password step
        data = conn.recv(1024)
        print(f"Received data (NEWPASS step): {data}")

        if not data.upper().startswith(b'NEWPASS'):
            conn.sendall(b'-ERR Expected NEWPASS command\r\n')
            return

        new_password = data.split()[1].decode('utf-8')
        print(f"Received new password: {new_password}")

        if update_password(email, new_password):
            conn.sendall(b'200 Password changed successfully\r\n')
        else:
            conn.sendall(b'-ERR Failed to update password\r\n')

    except Exception as e:
        print(f"Error handling client: {e}")
        conn.sendall(b'-ERR Server encountered an error\r\n')


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connection from {addr}")
                handle_client(conn)


if __name__ == "__main__":
    main()