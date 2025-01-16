import os  # For interacting with the operating system (creating files, generating random data)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # For AES encryption
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # For creating a secure key from a password
from cryptography.hazmat.primitives import hashes  # For hashing algorithms (SHA-256)
from cryptography.hazmat.primitives.hmac import HMAC  # For creating HMACs (Hash-based Message Authentication Codes)
from cryptography.hazmat.primitives.padding import PKCS7  # For padding the data to fit the AES block size
from cryptography.hazmat.backends import default_backend  # Cryptographic backend (default)
from cryptography.hazmat.primitives.asymmetric import rsa  # For RSA encryption
from cryptography.hazmat.primitives.asymmetric import padding  # For padding in RSA encryption
from cryptography.hazmat.primitives import serialization  # For reading and writing keys in PEM format
import json  # For saving metadata to a JSON file

# Define constants
SALT_LENGTH = 16  # Salt length used when creating a key from the password (salt is random data to prevent repeating keys)
AES_BLOCK_SIZE = 128  # AES block size in bits (128 bits = 16 bytes)
KEY_ROTATION_METADATA_FILE = "key_rotation_metadata.json"  # File where key version info is stored

# Load metadata about the keys (key rotation version and file paths)
def load_key_metadata():
    # If the metadata file exists, read it and return the contents
    if os.path.exists(KEY_ROTATION_METADATA_FILE):
        with open(KEY_ROTATION_METADATA_FILE, "r") as f:
            return json.load(f)
    # If the file doesn't exist, return an empty default metadata
    return {"current_version": 0, "keys": {}}

# Save the updated metadata to a JSON file
def save_key_metadata(metadata):
    with open(KEY_ROTATION_METADATA_FILE, "w") as f:
        json.dump(metadata, f, indent=4)  # Save metadata with nice indentation for readability

# Generate a cryptographic key from a password and salt (PBKDF2 key derivation function)
def derive_key(password: str, salt: bytes) -> bytes:
    # PBKDF2HMAC: A secure method to derive a key from a password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use the SHA-256 hash function
        length=32,  # Desired key length (32 bytes = 256 bits for AES-256)
        salt=salt,  # Use the salt to make the key derivation more secure
        iterations=100000,  # Number of iterations (higher = more secure)
        backend=default_backend()  # Use the default backend for cryptography
    )
    return kdf.derive(password.encode())  # Return the derived key as bytes

# Generate a new RSA public and private key pair
def generate_rsa_keys():
    # Generate a new RSA private key with a key size of 2048 bits
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Common value for the RSA public exponent
        key_size=2048,  # RSA key size (2048 bits is a secure, commonly used size)
        backend=default_backend()  # Default cryptographic backend
    )
    public_key = private_key.public_key()  # Derive the public key from the private key

    # Convert the private key to PEM format (this is a standard format for storing keys)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,  # PEM encoding (a readable format)
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # Private key format (standard OpenSSL format)
        encryption_algorithm=serialization.NoEncryption()  # No encryption on the private key file
    )

    # Convert the public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,  # PEM encoding
        format=serialization.PublicFormat.SubjectPublicKeyInfo  # Public key format
    )

    return private_pem, public_pem  # Return the private and public keys in PEM format

# Function to rotate the RSA keys (generate new keys and update metadata)
def rotate_rsa_keys():
    metadata = load_key_metadata()  # Load current key metadata
    new_version = metadata["current_version"] + 1  # Increase the version number for the new keys

    # Generate new RSA keys (private and public)
    private_key_pem, public_key_pem = generate_rsa_keys()

    # Save the new keys to files with the new version number in the file names
    private_key_path = f"private_key_v{new_version}.pem"  # File path for the private key
    public_key_path = f"public_key_v{new_version}.pem"  # File path for the public key

    with open(private_key_path, "wb") as private_file:
        private_file.write(private_key_pem)  # Write the private key to a file

    with open(public_key_path, "wb") as public_file:
        public_file.write(public_key_pem)  # Write the public key to a file

    # Update metadata with the new version and the file paths of the new keys
    metadata["current_version"] = new_version  # Set the new version number
    metadata["keys"][str(new_version)] = {
        "private_key": private_key_path,  # Save the private key file path
        "public_key": public_key_path  # Save the public key file path
    }

    save_key_metadata(metadata)  # Save the updated metadata to the JSON file
    print(f"Keys rotated to version {new_version}.")  # Print a message saying keys were rotated

# Function to encrypt the AES key using the RSA public key
def encrypt_aes_key_with_rsa(public_key_pem, aes_key):
    # Load the public RSA key from the PEM file
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

    # Encrypt the AES key using RSA and OAEP padding (secure encryption method for RSA)
    encrypted_aes_key = public_key.encrypt(
        aes_key,  # The AES key to be encrypted
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask generation function (for added security)
            algorithm=hashes.SHA256(),  # Hashing algorithm for OAEP
            label=None  # No label is used in OAEP encryption
        )
    )
    return encrypted_aes_key  # Return the encrypted AES key

# Function to sign the encrypted data using the RSA private key
def sign_data(private_key_pem, data):
    # Load the private RSA key from the PEM file
    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

    # Create a digital signature of the data using the private key and PSS padding (secure signing method)
    signature = private_key.sign(
        data,  # The data to sign (usually the encrypted data or a hash of the data)
        padding.PSS(  # PSS (Probabilistic Signature Scheme) padding
            mgf=padding.MGF1(hashes.SHA256()),  # Mask generation function for PSS
            salt_length=padding.PSS.MAX_LENGTH  # Maximum salt length for PSS
        ),
        hashes.SHA256()  # Use SHA-256 as the hashing algorithm for the signature
    )
    return signature  # Return the generated signature

# Function to encrypt a file using AES (for data encryption), RSA (for encrypting the AES key), and digital signatures
def encrypt_file(input_file: str, output_file: str, password: str):
    salt = os.urandom(SALT_LENGTH)  # Generate a random salt to make the key derivation more secure
    iv = os.urandom(16)  # Generate a random Initialization Vector (IV) for AES encryption

    # Derive the AES key from the password and salt using PBKDF2HMAC
    key = derive_key(password, salt)

    # Load the current RSA public key from the key metadata (based on the current version)
    metadata = load_key_metadata()
    current_version = metadata["current_version"]
    public_key_path = metadata["keys"][str(current_version)]["public_key"]

    with open(public_key_path, "rb") as public_file:
        public_key_pem = public_file.read()  # Read the public key from the file

    # Encrypt the AES key using the RSA public key
    encrypted_aes_key = encrypt_aes_key_with_rsa(public_key_pem, key)

    # Set up the AES cipher using CBC mode (block cipher mode)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()  # Create the encryptor object to perform encryption

    # Read the input file (plaintext) and encrypt it
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Pad the data to match the AES block size (AES needs data to be a multiple of the block size)
    padder = PKCS7(AES_BLOCK_SIZE).padder()  # Create the padding object
    padded_data = padder.update(plaintext) + padder.finalize()  # Pad the data to the block size

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Create an HMAC (Hash-based Message Authentication Code) for the ciphertext to verify integrity later
    hmac = HMAC(key, hashes.SHA256(), backend=default_backend())  # Create HMAC object
    hmac.update(ciphertext)  # Update HMAC with the encrypted data
    hmac_value = hmac.finalize()  # Finalize the HMAC (generate the HMAC value)

    # Prepare the data to be signed (includes the encrypted AES key, salt, IV, ciphertext, and HMAC)
    data_to_sign = encrypted_aes_key + salt + iv + ciphertext + hmac_value

    # Load the private RSA key from the metadata for signing the data
    private_key_path = metadata["keys"][str(current_version)]["private_key"]
    with open(private_key_path, "rb") as private_file:
        private_key_pem = private_file.read()  # Read the private key from the file

    # Sign the data using the private RSA key
    signature = sign_data(private_key_pem, data_to_sign)

    # Save the encrypted file with the necessary data: AES key, salt, IV, ciphertext, signature, and version info
    with open(output_file, 'wb') as f:
        # Write the version number, encrypted data, and signature to the output file
        f.write(current_version.to_bytes(4, "big") + data_to_sign + signature)

    print(f"Encryption completed. File saved at {output_file}.")  # Print a message when encryption is done

# Main function to control the process
def main():
    # Set the input file (the file to encrypt) and the output file (where the encrypted file will be saved)
    input_file = r'C:\Users\user\OneDrive\Desktop\C++ practice\crypto\example.txt'  # Path to your file
    encrypted_file = r'C:\Users\user\OneDrive\Desktop\C++ practice\crypto\example_encrypted.aes'  # Output path

    password = 'YourSecurePassword'  # The password used to encrypt the file

    # Rotate RSA keys if needed (generate and save new keys)
    rotate_rsa_keys()

    # Encrypt the file using the provided password
    encrypt_file(input_file, encrypted_file, password)

# Check if the script is being run directly (i.e., not imported as a module)
if __name__ == '__main__':
    main()  # Run the main function to start the encryption process
