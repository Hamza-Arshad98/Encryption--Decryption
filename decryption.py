import os  # For interacting with the operating system, such as file handling
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # For AES decryption
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # For generating a secure key from a password
from cryptography.hazmat.primitives import hashes  # For hashing (SHA-256)
from cryptography.hazmat.primitives.hmac import HMAC  # For HMAC (used for integrity check)
from cryptography.hazmat.primitives.padding import PKCS7  # For padding/unpadding the data (needed for AES)
from cryptography.hazmat.primitives.asymmetric import padding  # For RSA padding used during decryption
from cryptography.hazmat.primitives import serialization  # For reading/writing RSA keys in PEM format
import json  # For handling metadata and key rotation

SALT_LENGTH = 16  # Salt length used to create a key from the password
AES_BLOCK_SIZE = 128  # AES block size in bits (128 bits = 16 bytes)
KEY_ROTATION_METADATA_FILE = "key_rotation_metadata.json"  # File to store key rotation metadata
RSA_KEY_SIZE = 256  # Size of RSA key (in bytes), corresponding to 2048-bit key length

# Function to load key rotation metadata (contains version info and paths to RSA keys)
def load_key_metadata():
    if os.path.exists(KEY_ROTATION_METADATA_FILE):  # Check if metadata file exists
        with open(KEY_ROTATION_METADATA_FILE, "r") as f:
            return json.load(f)  # Return the metadata from the JSON file
    raise FileNotFoundError("Key rotation metadata not found.")  # Raise error if file is missing

# Function to decrypt the AES key using the RSA private key
def decrypt_aes_key_with_rsa(private_key_pem, encrypted_aes_key):
    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=None)  # Load private RSA key
    aes_key = private_key.decrypt(
        encrypted_aes_key,  # The encrypted AES key
        padding.OAEP(  # Use OAEP padding scheme (Optimal Asymmetric Encryption Padding)
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # MGF1 mask generation function with SHA-256
            algorithm=hashes.SHA256(),  # Use SHA-256 as the hashing algorithm
            label=None  # No label used for padding
        )
    )
    return aes_key  # Return the decrypted AES key

# Function to verify the data's integrity by checking the signature with the RSA public key
def verify_signature(public_key_pem, data, signature):
    public_key = serialization.load_pem_public_key(public_key_pem, backend=None)  # Load RSA public key
    public_key.verify(
        signature,  # The signature to verify
        data,  # The data that was signed
        padding.PSS(  # Use PSS padding scheme (Probabilistic Signature Scheme)
            mgf=padding.MGF1(hashes.SHA256()),  # MGF1 with SHA-256 for mask generation
            salt_length=padding.PSS.MAX_LENGTH  # Max salt length
        ),
        hashes.SHA256()  # Use SHA-256 for hash function
    )

# Function to decrypt the file encrypted with AES, HMAC, and RSA for AES key
def decrypt_file(encrypted_file: str, output_file: str, password: str):
    with open(encrypted_file, 'rb') as f:
        # Read and parse the encrypted file structure
        version = int.from_bytes(f.read(4), "big")  # Read the version number of the key (4 bytes)
        metadata = load_key_metadata()  # Load the key rotation metadata

        # Get paths of the private and public keys for the current version
        private_key_path = metadata["keys"][str(version)]["private_key"]
        public_key_path = metadata["keys"][str(version)]["public_key"]

        with open(private_key_path, "rb") as private_file:  # Open the private key file
            private_key_pem = private_file.read()  # Read the private key PEM
        with open(public_key_path, "rb") as public_file:  # Open the public key file
            public_key_pem = public_file.read()  # Read the public key PEM

        # Read the encrypted AES key (fixed size based on RSA key size)
        encrypted_aes_key = f.read(RSA_KEY_SIZE)
        salt = f.read(SALT_LENGTH)  # Read the salt used for key derivation
        iv = f.read(16)  # Read the initialization vector (IV) for AES (16 bytes for AES)
        ciphertext_and_hmac = f.read()  # Read the rest of the file containing ciphertext + HMAC
        signature = ciphertext_and_hmac[-256:]  # The last 256 bytes are the signature
        ciphertext_and_hmac = ciphertext_and_hmac[:-256]  # Exclude the signature for now

        # Extract ciphertext and HMAC from the rest of the data
        ciphertext = ciphertext_and_hmac[:-32]  # The ciphertext is everything except the last 32 bytes
        hmac_value = ciphertext_and_hmac[-32:]  # The last 32 bytes are the HMAC

        # Verify the signature to ensure data integrity
        data_to_verify = encrypted_aes_key + salt + iv + ciphertext + hmac_value
        verify_signature(public_key_pem, data_to_verify, signature)

        # Decrypt the AES key using the RSA private key
        key = decrypt_aes_key_with_rsa(private_key_pem, encrypted_aes_key)

        # Verify the HMAC to ensure the ciphertext wasn't tampered with
        hmac = HMAC(key, hashes.SHA256())  # Create an HMAC object using the AES key and SHA-256
        hmac.update(ciphertext)  # Update the HMAC with the ciphertext
        hmac.verify(hmac_value)  # Verify the HMAC (raises error if mismatched)

        # Decrypt the ciphertext using AES in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))  # Set up the AES cipher with CBC mode
        decryptor = cipher.decryptor()  # Create a decryptor object to decrypt the data
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()  # Decrypt the ciphertext

        # Remove the padding added during encryption
        unpadder = PKCS7(AES_BLOCK_SIZE).unpadder()  # Set up the unpadder for AES
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()  # Unpad the data

        # Write the decrypted plaintext to the output file
        with open(output_file, 'wb') as output:
            output.write(plaintext)  # Write the decrypted plaintext to the output file

        print(f"Decryption completed. File saved at {output_file}.")  # Print completion message

def main():
    # Specify the paths to the encrypted file and where the decrypted file should be saved
    encrypted_file = r'C:\Users\user\OneDrive\Desktop\C++ practice\crypto\example_encrypted.aes'
    decrypted_file = r'C:\Users\user\OneDrive\Desktop\C++ practice\crypto\example_decrypted.txt'

    password = 'YourSecurePassword'  # The password used for key derivation (same one as used in encryption)

    # Perform the decryption
    decrypt_file(encrypted_file, decrypted_file, password)

if __name__ == '__main__':
    main()  # Run the main function when the script is executed
