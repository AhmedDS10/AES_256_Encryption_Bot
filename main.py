import os
import telebot
from flask import Flask, request
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Initialize Flask app
app = Flask(__name__)

# Initialize the bot with your Telegram Bot Token from environment variable
bot = telebot.TeleBot(os.getenv("BOT_TOKEN"))

# Dictionary to store user passwords and keys
user_keys = {}

# Function to generate a key from a password
def generate_key(password):
    salt = b'some_salt'  # Use a unique salt for better security
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Function to encrypt text using AES-256
def encrypt_text(text, key):
    iv = os.urandom(16)  # Generate a random 128-bit IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data  # Return IV + encrypted data

# Function to decrypt text using AES-256
def decrypt_text(encrypted_data, key):
    iv = encrypted_data[:16]  # Extract the IV from the beginning
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    text = unpadder.update(padded_data) + unpadder.finalize()
    return text.decode()

# Command to start the bot
@bot.message_handler(commands=['start'])
def send_welcome(message):
    bot.reply_to(message, "Welcome! Send /setpassword to set your encryption password.")

# Command to set the encryption password
@bot.message_handler(commands=['setpassword'])
def set_password(message):
    bot.reply_to(message, "Please enter your encryption password:")
    bot.register_next_step_handler(message, process_password)

def process_password(message):
    user_id = message.from_user.id
    password = message.text
    key = generate_key(password)
    user_keys[user_id] = key
    bot.reply_to(message, "Password set! You can now send /encrypt or /decrypt commands.")

# Command to encrypt text
@bot.message_handler(commands=['encrypt'])
def encrypt_message(message):
    bot.reply_to(message, "Please enter the text you want to encrypt:")
    bot.register_next_step_handler(message, process_encrypt)

def process_encrypt(message):
    user_id = message.from_user.id
    if user_id not in user_keys:
        bot.reply_to(message, "Please set a password first using /setpassword.")
        return
    text = message.text
    key = user_keys[user_id]
    encrypted_data = encrypt_text(text, key)
    bot.reply_to(message, f"Encrypted text (in bytes): {encrypted_data.hex()}")

# Command to decrypt text
@bot.message_handler(commands=['decrypt'])
def decrypt_message(message):
    bot.reply_to(message, "Please enter the encrypted text (in hex format):")
    bot.register_next_step_handler(message, process_decrypt)

def process_decrypt(message):
    user_id = message.from_user.id
    if user_id not in user_keys:
        bot.reply_to(message, "Please set a password first using /setpassword.")
        return
    encrypted_hex = message.text
    try:
        encrypted_data = bytes.fromhex(encrypted_hex)
        key = user_keys[user_id]
        decrypted_text = decrypt_text(encrypted_data, key)
        bot.reply_to(message, f"Decrypted text: {decrypted_text}")
    except Exception as e:
        bot.reply_to(message, "Invalid encrypted text. Please try again.")

# Webhook route
@app.route('/webhook', methods=['POST'])
def webhook():
    update = telebot.types.Update.de_json(request.stream.read().decode('utf-8'))
    bot.process_new_updates([update])
    return 'ok', 200

# Health check route
@app.route('/')
def home():
    return "Bot is running!"

# Set webhook on startup
def set_webhook():
    bot.remove_webhook()
    bot.set_webhook(url=f"https://{os.getenv('RENDER_EXTERNAL_HOSTNAME')}/webhook")

# Run the Flask app
if __name__ == '__main__':
    set_webhook()
    app.run(host='0.0.0.0', port=8080)
