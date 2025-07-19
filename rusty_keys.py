from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime

import argparse
import getpass
import os
import sys


class RustyKeys:
    def __init__(self, args):
        self.args = args
        self.time = self.get_time()

    def run(self):
        verbose = self.args.verbose

        if self.args.private_key or self.args.generate_keys:
            password = str.encode(getpass.getpass('Enter password for private key: '))

        if self.args.private_key:
            private = self.fetch_private_key(password, self.args.private_key, verbose)
        if self.args.public_key:
            public = self.fetch_public_key(self.args.public_key, verbose)

        if self.args.generate_keys:
            _, _, private, public = self.generate_suite(password, verbose)
            self.store_keys(private, public, self.time, self.args.output_private, self.args.output_public, verbose)
        
        if self.args.encrypt_file:
            self.token = self.fetch_token(self.args.encrypt_file, verbose)

        if self.args.encrypt_input or self.args.encrypt_file:
            token = self.encrypt_password(public, self.args.encrypt_input, self.args.encrypt_file, verbose)
            self.store_encrypted_password(token, self.time, self.args.output_encryption, verbose)

        if self.args.decrypt_file:
            decrypted_token = self.decrypt(private, password, self.args.decrypt_file, verbose)
            print(decrypted_token.decode())

        if self.args.generate_string:
            random_string = self.generate_string(self.args.generate_string, verbose)
            print(random_string)

    def fetch_private_key(self, password, v_path, verbose=False):
        dir = os.path.join(os.getcwd(), v_path)

        try:
            with open(v_path, 'rb') as f:
                private_key = f.read()
                f.close()
                private = serialization.load_pem_private_key(
                    private_key,
                    password=password,
                    backend=default_backend()
                )
            if verbose:
                print(f"Successfully read private key from {dir}")
        except Exception as e:
            e_type = e.__class__.__name__
            if e_type == 'ValueError':
                print("Incorrect password or private key")
                sys.exit(1)
            else:
                print(f"{e_type} fetching private key from {dir}: {e}")

        return private
            
    def fetch_public_key(self, u_path, verbose=False):
        dir = os.path.join(os.getcwd(), u_path)

        try:
            with open(u_path, 'rb') as f:
                public_key = f.read()
                f.close()
                public = serialization.load_pem_public_key(
                    public_key,
                    backend=default_backend()
                )
            if verbose:
                print(f"Successfully read public key from {dir}")
        except Exception as e:
            print(f"Error fetching public key from {dir}: {e}")
        
        return public
    
    def generate_suite(self, password, verbose=False):
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            public_key = private_key.public_key()

            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(password)
            )

            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if verbose:
                print("Successfully generated key suite")
        except Exception as e:
            print(f"{e.__class__.__name__} in generating suite: {e}")

        return private_key, public_key, pem, public_pem

    def store_keys(self, private, public, time=None, priv_path=None, pub_path=None, verbose=False):
        if priv_path is None:
            priv_path = f'./private_key{time}'
        if pub_path is None:
            pub_path = f"./public_key{time}.pub"

        try:
            with open(priv_path, 'wb') as f:
                f.write(private)
                f.close()
                if verbose:
                    print(f"Successfully wrote private key to {priv_path}")
        except Exception as e:
            print(f"Error writing private key to {priv_path}: {e}")

        try:
            with open(pub_path, 'wb') as f:
                f.write(public)
                f.close()
                if verbose:
                    print(f"Successfully wrote public key to {pub_path}")
        except Exception as e:
            print(f"Error writing public key to {pub_path}: {e}")

    def fetch_token(self, token_file, verbose=False):
        try:
            with open(token_file, 'rb') as f:
                token = f.read()
                f.close()
                if verbose:
                    print(f"Password token successfully read from {token_file}")
        except Exception as e:
            print(f"Error reading token from {token_file}: {e}")

        return token
    
    def encrypt_password(self, public_key, p_flag=False, password_file=None, verbose=False):
        if p_flag:
            password = str.encode(getpass.getpass("Password to encrypt: "))
        elif password_file:
            try:
                with open(password_file, 'rb') as f:
                    password = f.read()
                    f.close()
                    if verbose:
                        print("Successfully read password from file... encrypting now")
            except Exception as e:
                    print(f"Error while reading password from {password_file}: {e}")

        try:
            cipher_text = public_key.encrypt(
                password,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                )
            )
            if verbose:
                print("Successfully encrypted password... writing to file now")
        except Exception as e:
                if e.__class__.__name__ == 'AttributeError':
                    print("Must provide a public key in order to encrypt text")
                    sys.exit(1)
                else:
                    print(f"Error encrypting password: {e}")

        return cipher_text
    
    def store_encrypted_password(self, token, time, password_file=None, verbose=False):
        if password_file is None:
            password_file = f"./encrypted_token_{time}"
        try:
            with open(password_file, 'wb') as f:
                f.write(token)
                f.close()
                if verbose:
                    print(f"Successfully wrote encrypted password to {password_file}")
        except Exception as e:
            print(f"Error writing encrypted password to {password_file}: {e}")

    def decrypt(self, private_key, token, token_file=None, verbose=False):
        if token_file:
            try:
                with open(token_file, 'rb') as f:
                    plain_text = private_key.decrypt(
                        f.read(),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    f.close()
                    if verbose:
                        print("Successfully decrypted token")
            except Exception as e:
                print(f"Error reading and decrypting token file: {e}")
        else:
            try:
                plain_text = private_key.decrypt(
                    token,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                if verbose:
                    print("Successfully decrypted password")
            except Exception as e:
                print(f"Error decrypting password: {e}")

        return plain_text
    
    def generate_string(self, str_length, verbose=False):
        import random
        import string

        characters = string.ascii_letters + string.digits + ' !@#$_'
        random_string = ''.join(random.choice(characters) for i in range(str_length))
        if verbose:
            print(f"Successfully generated {str_length} character random string")

        return random_string
    
    def get_time(self):
        current_time = datetime.now()
        file_time = current_time.strftime("%m-%d_%H:%M:%S")

        return file_time


def main():
    parser = argparse.ArgumentParser(
        prog="rustyKeys",
        description="home forged cryptography",
    )
    parser.add_argument('-i', '--private-key', nargs='?', help='file path to private key pem')
    parser.add_argument('-I', '--public-key', nargs='?', help='file path to public key pem')
    parser.add_argument('-g', '--generate-keys', action='store_true', help='generate private and public key')
    parser.add_argument('-p', '--output-private', nargs='?', help='file to output generated private pem to')
    parser.add_argument('-P', '--output-public', nargs='?', help='file to output generated public pem to')
    parser.add_argument('-e', '--encrypt-file', nargs='?', help='input file to encrypt')
    parser.add_argument('-E', '--encrypt-input', action='store_true', help='input to encrypt')
    parser.add_argument('-o', '--output-encryption', nargs='?', help='file to output encryption to')
    parser.add_argument('-d', '--decrypt-file', nargs='?', help='input file to decrypt')
    parser.add_argument('-s', '--generate-string', nargs='?', type=int, help='generate random, variable length string for whatever reason')
    parser.add_argument('-v', '--verbose', action='store_true', help='output verbosity')
    args = parser.parse_args()

    if len(sys.argv) < 2:
        print(parser.print_help())
        sys.exit(1)

    rusty_keys = RustyKeys(args)
    rusty_keys.run()


if __name__ == '__main__':
    main()