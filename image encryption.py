
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from PIL import Image 
import os
import base64
from io import BytesIO
import secrets


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)


def encrypt_image(image_path: str, password: str) -> bytes:
   
    with Image.open(image_path) as img:
        img_byte_arr = BytesIO()
        img.save(img_byte_arr, format=img.format)
        image_data = img_byte_arr.getvalue()

    
    salt = secrets.token_bytes(16)
    key = derive_key(password.encode(), salt)

    
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()


    encrypted_data = encryptor.update(image_data) + encryptor.finalize()

    
    encrypted_image_data = salt + iv + encrypted_data
    data = base64.b64encode(encrypted_image_data)
    return data


def save_encrypted_image(encrypted_data: bytes, output_path: str):
    with open(output_path, "wb") as f:
        f.write(encrypted_data)


def decrypt_image(encrypted_image_path: str, password: str) -> Image.Image:
    data = base64.b64decode(encrypted_data)
    with open(data, "rb") as f:
        encrypted_data = f.read()
        

   
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_image_data = encrypted_data[32:]

    
    key = derive_key(password.encode(), salt)

    
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    
    decrypted_data = decryptor.update(encrypted_image_data) + decryptor.finalize()

    
    img = Image.open(BytesIO(decrypted_data))
    return img


if __name__ == "__main__":
    
    image_path = input("path/to/your/image.jpg:   ")
    encrypted_image_path = r"C:\Users\Benwari Ezekiel\Pictures"
    password = input("your_secure_password: ")

   
    encrypted_data = encrypt_image(image_path, password)
    save_encrypted_image(encrypted_data, encrypted_image_path)
    print(f"Image encrypted and saved to {encrypted_image_path}")

    
    decrypted_image = decrypt_image(encrypted_image_path, password)
    decrypted_image.show()  

