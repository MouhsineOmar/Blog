import math
import random
import numpy as np
from flask import Flask, render_template, request
import codecs

app = Flask(__name__)

# ... Les fonctions de chiffrement César, multiplication, affine, Vigenère, Hill et transposition

# Will use codecs, as 'str' object in Python 3 doesn't have any attribute 'decode'

def generate_keypair(p, q, e):
    n = p * q
    phi_n = (p - 1) * (q - 1)
    d = mod_inverse(e, phi_n)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

# Fonction pour chiffrer le message
def encrypt(message, public_key):
    e, n = public_key
    cipher_text = [pow(char, e, n) for char in message]
    return cipher_text

# Fonction pour déchiffrer le message
def decrypt(cipher_text, private_key):
    d, n = private_key
    decrypted_text = [pow(char, d, n) for char in cipher_text]
    return decrypted_text

# Fonction pour convertir un message en ASCII
def text_to_ascii(message):
    return [ord(char) for char in message]

# Fonction pour convertir ASCII en texte
def ascii_to_text(ascii_list):
    return ''.join([chr(char) for char in ascii_list])

# Route for RSA encryption and decryption




def chiffrement_cesar(texte, decalage):
    texte_chiffre = []
    for char in texte:
        if char.isalpha():
            if char.isupper():
                texte_chiffre.append(chr((ord(char) + decalage - 65) % 26 + 65))
            else:
                texte_chiffre.append(chr((ord(char) + decalage - 97) % 26 + 97))
        else:
            texte_chiffre.append(char)
    texte_chiffre = "".join(texte_chiffre)
    return texte_chiffre

def dechiffrement_cesar(texte_chiffre, decalage):
    return chiffrement_cesar(texte_chiffre, -decalage)

def chiffr_affine(textpl, cle1, cle2):
    text_chiffre = []
    key = math.gcd(cle1, 26)

    if key == 1:
        for ch in textpl:
            if ch.isalpha():
                if ch.isupper():
                    text_chiffre.append(chr((((ord(ch) - 65) * cle1) + cle2) % 26 + 65))
                else:
                    text_chiffre.append(chr((((ord(ch) - 97) * cle1) + cle2) % 26 + 97))
            else:
                text_chiffre.append(ch)
    else:
        return "Your key is not valid. Please choose another key like {1,3,5,7,9,11,15,17,19,21,23, 25}"

    text_chiffre = "".join(text_chiffre)
    return text_chiffre

def dechiffrement_affine(texte_chiff, cle1, cle2):
    texte_chiffre = []
    k1 = mod_inverse(cle1, 26)
    for ch in texte_chiff:
        if ch.isalpha():
            if ch.isupper():
                texte_chiffre.append(chr((((ord(ch) - 65) * k1) - (k1 * cle2)) % 26 + 65))
            else:
                texte_chiffre.append(chr((((ord(ch) - 97) * k1) - (k1 * cle2)) % 26 + 97))
        else:
            texte_chiffre.append(ch)

    texte_chiffre = "".join(texte_chiffre)
    return texte_chiffre

def mod_inverse(a, m):
    g = math.gcd(a, m)
    if g != 1:
        raise ValueError(f"{a} n'a pas d'inverse modulo {m}")
    else:
        return pow(a, -1, m)
    
def chiffrement_vigenere(texte, cle):
    texte_chiffre = []
    cle_etendue = (cle * (len(texte) // len(cle) + 1))[:len(texte)]

    for char, cle_char in zip(texte, cle_etendue):
        if char.isalpha():
            decalage = ord(cle_char.upper()) - 65
            if char.isupper():
                texte_chiffre.append(chr((ord(char) + decalage - 65) % 26 + 65))
            else:
                texte_chiffre.append(chr((ord(char) + decalage - 97) % 26 + 97))
        else:
            texte_chiffre.append(char)

    texte_chiffre = "".join(texte_chiffre)
    return texte_chiffre

def dechiffrement_vigenere(texte_chiffre, cle):
    texte_dechiffre = []
    cle_etendue = (cle * (len(texte_chiffre) // len(cle) + 1))[:len(texte_chiffre)]

    for char, cle_char in zip(texte_chiffre, cle_etendue):
        if char.isalpha():
            decalage = ord(cle_char.upper()) - 65
            if char.isupper():
                texte_dechiffre.append(chr((ord(char) - decalage - 65) % 26 + 65))
            else:
                texte_dechiffre.append(chr((ord(char) - decalage - 97) % 26 + 97))
        else:
            texte_dechiffre.append(char)

    texte_dechiffre = "".join(texte_dechiffre)
    return texte_dechiffre

#############################################################################################################

def encrypt_transposition_simple(message, permutation):
    message = message.replace(" ", "").replace("'", "")
    
    block_size = len(permutation)

    blocks = [message[i:i+block_size] for i in range(0, len(message), block_size)]

    encrypted_blocks = [''.join(block[permutation[i]-1] for i in range(block_size)) for block in blocks]

    encrypted_message = ''.join(encrypted_blocks)

    return encrypted_message

def decrypt_transposition_simple(encrypted_message, permutation):
    block_size = len(permutation)

    # Calculer le nombre de blocs
    num_blocks = len(encrypted_message) // block_size

    # Initialiser une liste pour stocker les blocs déchiffrés
    decrypted_blocks = []

    for i in range(num_blocks):
        # Extraire chaque bloc
        block = encrypted_message[i * block_size: (i + 1) * block_size]

        # Créer une liste d'indices des colonnes triées par l'ordre alphabétique des lettres de la permutation
        sorted_columns = sorted(range(block_size), key=lambda x: permutation[x])

        # Appliquer la permutation inverse
        decrypted_block = ''.join(block[sorted_columns[j]] for j in range(block_size))

        # Ajouter le bloc déchiffré à la liste
        decrypted_blocks.append(decrypted_block)

    # Concaténer les blocs déchiffrés pour obtenir le message déchiffré final
    decrypted_message = ''.join(decrypted_blocks)

    return decrypted_message





@app.route('/transposition_simple', methods=['GET', 'POST'])
def transposition_simple():
    if request.method == 'POST':
        try:
            texte = request.form['texte']
            permutation = list(map(int, request.form['permutation'].split()))
            action = request.form['action']

            if action == 'chiffrement' or action == 'dechiffrement':
                if action == 'chiffrement':
                    resultat = encrypt_transposition_simple(texte, permutation)
                else:
                    resultat = decrypt_transposition_simple(texte, permutation)

                return render_template('transposition_simple.html', resultat=resultat)
            else:
                return "Action non reconnue."
        except Exception as e:
            error_message = f"Une erreur s'est produite : {str(e)}"
            return render_template('transposition_simple.html', resultat=error_message)

    return render_template('transposition_simple.html', resultat=None)

############################################################################################################

def matrix_mod_inv(matrix, modulus):
    det = int(np.round(np.linalg.det(matrix)))
    
    if det == 0 or np.gcd(det, modulus) != 1:
        raise ValueError("Matrix is not invertible modulo the given modulus.")
    
    det_inv = pow(det, -1, modulus)
    adjugate = (det_inv * np.round(det * np.linalg.inv(matrix))).astype(int)
    inverse = (adjugate % modulus + modulus) % modulus  # Ensure the result is positive
    return inverse




def encrypt_hill(message, key_matrix):
    n = len(key_matrix)
    message = [ord(char) - ord('A') for char in message.upper() if char.isalpha()]
    message = np.array(message)
    padding = (n - len(message) % n) % n  # Calculate the necessary padding
    message = np.pad(message, (0, padding), mode='constant')
    message = message.reshape(-1, n)

    encrypted_message = ""
    for block in message:
        encrypted_block = np.dot(block, key_matrix) % 26
        encrypted_message += ''.join([chr(char + ord('A')) for char in encrypted_block])

    return encrypted_message


def decrypt_hill(ciphertext, key_matrix):
    key_inverse = matrix_mod_inv(key_matrix, 26)


    n = len(key_matrix)
    ciphertext = [ord(char) - ord('A') for char in ciphertext.upper() if char.isalpha()]
    ciphertext = np.array(ciphertext)
    ciphertext = ciphertext.reshape(-1, n)

    decrypted_message = ""
    for block in ciphertext:
        decrypted_block = np.dot(block, key_inverse) % 26
        decrypted_message += ''.join([chr(char + ord('A')) for char in decrypted_block])

    # Trim any trailing padding
    decrypted_message = decrypted_message.rstrip('A')

    return decrypted_message




def encrypt_transposition(message, key):
    message = ''.join(char.upper() for char in message if char.isalpha())
    block_size = len(key)
    message += ' ' * (block_size - len(message) % block_size)
    matrix = [list(message[i:i + block_size]) for i in range(0, len(message), block_size)]
    
    # Créer une liste d'indices des colonnes triées par l'ordre alphabétique des lettres de la clé
    sorted_columns = sorted(range(block_size), key=lambda x: key[x])
    
    # Construire le message chiffré en lisant les colonnes triées
    ciphertext = ''.join(''.join(matrix[row][col] for row in range(len(matrix))) for col in sorted_columns)
    
    return ciphertext




def decrypt_transposition(ciphertext, key):
    block_size = len(key)
    
    # Create a list of indices of columns sorted by the alphabetical order of key letters
    sorted_columns = sorted(range(block_size), key=lambda x: key[x])
    
    # Calculate the block count based on the length of the ciphertext and block size
    block_count = len(ciphertext) // block_size
    
    # Build the block matrix from the ciphertext
    matrix = [list(ciphertext[i*block_size:(i+1)*block_size]) for i in range(block_count)]
    
    # Invert the encryption process by sorting columns back to the original order
    original_columns = sorted(range(block_size), key=lambda x: sorted_columns[x])
    
    # Reconstruct the decrypted message by reading the sorted columns
    decrypted_message = ''.join(''.join(matrix[row][col] for col in original_columns) for row in range(block_count))
    
    return decrypted_message

##################################################__permutation__#############################""

def generate_permutation_table():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    permutation_table = random.sample(alphabet, len(alphabet))
    return permutation_table

def encryption_permutation(plaintext, permutation_table):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            index = ord(char.upper()) - ord('A')
            encrypted_char = permutation_table[index]
            if char.islower():
                encrypted_char = encrypted_char.lower()
            ciphertext += encrypted_char
        else:
            ciphertext += char
    return ciphertext

def decryption_permutation(ciphertext, permutation_table):
    inverse_permutation_table = {v: k for k, v in zip(permutation_table, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")}

    decrypted_text = ""
    for char in ciphertext:
        if char.isalpha():
            index = permutation_table.index(char.upper())
            decrypted_char = chr(index + ord('A'))
            if char.islower():
                decrypted_char = decrypted_char.lower()
            decrypted_text += decrypted_char
        else:
            decrypted_text += char
    return decrypted_text

@app.route('/permutation', methods=['GET', 'POST'])
def permutation():
    if request.method == 'POST':
        texte = request.form['texte']
        action = request.form['action']

        if action == 'encryption' or action == 'decryption':
            permutation_table = generate_permutation_table()

            if action == 'encryption':
                resultat = encryption_permutation(texte, permutation_table)
            elif action == 'decryption':
                resultat = decryption_permutation(texte, permutation_table)

            return render_template('permutation.html', resultat=resultat, permutation_table=permutation_table)
        else:
            return "Action non reconnue."

    return render_template('permutation.html', resultat=None, permutation_table=None)

##############################################################################################

@app.route('/transposition', methods=['GET', 'POST'])
def transposition():
    if request.method == 'POST':
        texte = request.form['texte']
        cle = request.form['cle']
        action = request.form['action']

        if action == 'chiffrement' or action == 'dechiffrement':
            if action == 'chiffrement':
                resultat = encrypt_transposition(texte, cle)
            else:
                resultat = decrypt_transposition(texte, cle)
            return render_template('transposition.html', resultat=resultat)
        else:
            return "Action non reconnue."

    return render_template('transposition.html', resultat=None)


@app.route('/hill', methods=['GET', 'POST'])
def hill():
    if request.method == 'POST':
        texte = request.form['texte']
        cle = request.form['cle']
        action = request.form['action']

        try:
            key_matrix = np.array([int(num) for num in cle.split()]).reshape(2, 2)
            key_inverse = matrix_mod_inv(key_matrix, 26)
        except ValueError as e:
            return f"Erreur lors de la lecture de la clé : {e}"

        if action == 'chiffrement' or action == 'dechiffrement':
            if action == 'chiffrement':
                resultat = encrypt_hill(texte, key_matrix)
            else:
                resultat = decrypt_hill(texte, key_matrix)  # Use key_matrix for decryption

            return render_template('hill.html', resultat=resultat, key_matrix=cle)
    else:
        return "Action non reconnue."


    return render_template('hill.html', resultat=None, key_matrix=None)





@app.route('/vigenere', methods=['GET', 'POST'])
def vigenere():
    if request.method == 'POST':
        texte = request.form['texte']
        cle = request.form['cle']
        action = request.form['action']

        if action == 'chiffrement' or action == 'dechiffrement':
            if action == 'chiffrement':
                resultat = chiffrement_vigenere(texte, cle)
            else:
                resultat = dechiffrement_vigenere(texte, cle)
            return render_template('vigenere.html', resultat=resultat)
        else:
            return "Action non reconnue."

    return render_template('vigenere.html', resultat=None)

@app.route('/cesar', methods=['GET', 'POST'])
def cesar():
    if request.method == 'POST':
        texte = request.form['texte']
        cle = int(request.form['cle'])
        action = request.form['action']

        if action == 'chiffrement' or action == 'dechiffrement':
            if action == 'chiffrement':
                resultat = chiffrement_cesar(texte, cle)
            elif action == 'dechiffrement':
                resultat = dechiffrement_cesar(texte, cle)

            return render_template('cesar.html', resultat=resultat, action=action)

        else:
            return "Action non reconnue."

    return render_template('cesar.html', resultat=None, action=None)


        
@app.route('/affine', methods=['GET', 'POST'])
def affine():
    if request.method == 'POST':
        texte = request.form['texte']
        cle1 = int(request.form['cle1'])
        cle2 = int(request.form['cle2'])
        action = request.form['action']

        if action == 'chiffrement' or action == 'dechiffrement':
            if action == 'chiffrement':
                resultat = chiffr_affine(texte, cle1, cle2)
            elif action == 'dechiffrement':
                resultat = dechiffrement_affine(texte, cle1, cle2)
            return render_template('affine.html', resultat=resultat)
        else:
            return "Action non reconnue."

    return render_template('affine.html', resultat=None)

###################################__multiplication__##################################################

@app.route('/multiplication', methods=['GET', 'POST'])
def multiplication():
    if request.method == 'POST':
        texte = request.form['texte']
        cle = int(request.form['cle'])
        action = request.form['action']
        
        if action == 'chiffrement' or action == 'dechiffrement':
            resultat = chiffr_multiplication(texte, cle, action)  # Corrected typo here
            return render_template('multiplication.html', resultat=resultat)
        else:
            return "Action non reconnue."

    return render_template('multiplication.html', resultat=None)


def chiffr_multiplication(texte, cle, mode):
    text_result = []
    key = math.gcd(cle, 26)

    if key == 1:
        inv = mod_inversee(cle, 26)

        for ch in texte:
            if ch.isalpha():
                if ch.isupper():
                    if mode == 'chiffrement':
                        text_result.append(chr(((ord(ch) - 65) * cle) % 26 + 65))
                    elif mode == 'dechiffrement':
                        text_result.append(chr(((ord(ch) - 65) * inv) % 26 + 65))
                else:
                    if mode == 'chiffrement':
                        text_result.append(chr(((ord(ch) - 97) * cle) % 26 + 97))
                    elif mode == 'dechiffrement':
                        text_result.append(chr(((ord(ch) - 97) * inv) % 26 + 97))
            else:
                text_result.append(ch)
    else:
        return "Your key is not valid. Please choose another key like {1,3,5,7,9,11,15,17,19,21,23, 25}"

    text_result = "".join(text_result)
    return text_result

def mod_inversee(a, m):
    
    g = math.gcd(a, m)
    if g != 1:
        raise ValueError(f"{a} n'a pas d'inverse modulo {m}")
    else:
        return pow(a, -1, m)
    
##########################################################################
#########################__AES__###########################################
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

    
def get_valid_key(key):
    if len(key) == 32 and all(c in "0123456789abcdefABCDEF" for c in key):
        return bytes.fromhex(key)
    else:
        return None

def get_valid_plaintext(plaintext):
    if len(plaintext) == 32 and all(c in "0123456789abcdefABCDEF" for c in plaintext):
        return bytes.fromhex(plaintext)
    else:
        return None

def encrypt_text(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def decrypt_text(ciphertext, key):
    decipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded = decipher.decrypt(ciphertext)
    return decrypted_padded

@app.route("/aes", methods=["GET", "POST"])
def aes():
    if request.method == "POST":
        choice = request.form.get("choice")
        key = get_valid_key(request.form.get("key"))
        plaintext = get_valid_plaintext(request.form.get("plaintext"))

        if key is None or plaintext is None:
            error_message = "La clé et le texte clair doivent avoir une longueur de 32 caractères hexadécimaux (128 bits)."
            return render_template("aes.html", error_message=error_message)

        if choice == "E":
            ciphertext = encrypt_text(key, plaintext)
            return render_template("aes.html", choice=choice, ciphertext=ciphertext.hex()[:32])

        elif choice == "D":
            decrypted_text = decrypt_text(plaintext, key)
            return render_template("aes.html", choice=choice, decrypted_text=decrypted_text.hex()[:32])

    return render_template("aes.html")

###################################################################################

##########################--RC4--####################################################

def initialize_vectors(K, n):
    S = list(range(n))
    length = len(K)
    T = [int(bit) for bit in K] * (n // length) + [int(bit) for bit in K[:n % length]]
    return S, T

def swap_values(S, i, j):
    S[i], S[j] = S[j], S[i]

def key_scheduling(S, T, n):
    j = 0
    for i in range(n):
        j = (j + S[i] + T[i]) % n
        swap_values(S, i, j)

def pseudo_random_generation(S, n):
    i = 0
    j = 0
    keystream = []
    for _ in range(4):  # Generate 4 keystream values
        i = (i + 1) % n
        j = (j + S[i]) % n
        swap_values(S, i, j)
        t = (S[i] + S[j]) % n
        k = S[t]
        keystream.append(k)
    return keystream

def encrypte(plaintext, keystream, n):
    K = [int(bit) for bit in keystream.split(',')]
    P = [int(bit) for bit in plaintext.split(',')]
    S, T = initialize_vectors(K, n)
    key_scheduling(S, T, n)
    keystream = pseudo_random_generation(S, n)
    ciphertext = [k ^ p for k, p in zip(keystream, P)]
    return ciphertext,keystream

def decrypte(ciphertext, keystream, n):
    decrypted,keystream = encrypte(ciphertext, keystream, n)
    return decrypted,keystream








@app.route('/rcc4', methods=['GET', 'POST'])
def rcc4():
    if request.method == 'POST':
        try:
            key = request.form['key']
            action = request.form['action']
            text = request.form['plaintext']
            n = int(request.form['n'])

            # Perform Encryption or Decryption
            if action == 'chiffrement':
                result,keystream = encrypte(text, key, n)
            else:
                result,keystream = decrypte(text, key, n)

            return render_template('rcc4.html', result=result, key_stream=keystream, key=key, text=text, action=action)

        except Exception as e:
            error_message = f"An error occurred: {str(e)}"
            return render_template('rcc4.html', error_message=error_message)

    return render_template('rcc4.html', result=None, key_stream=None, key=None, text=None, action=None)
#####################################################################################

##########################__RSA__#####################################################

def gcdrsa(a, b):
     while b != 0:
         a, b = b, a % b
     return a

def modinvrsa(a, m):
     m0, x0, x1 = m, 0, 1
     while a > 1:
         q = a // m
         m, a = a % m, m
         x0, x1 = x1 - q * x0, x0
     return x1 + m0 if x1 < 0 else x1

def encryptRsa(message, p, q, e):
     n = p * q
     phi = (p - 1) * (q - 1)
     if gcdrsa(e, phi) != 1:
         raise ValueError("e and phi are not coprime.")
    
     cipher_text = pow(message, e, n)
     return cipher_text

def decryptRsa(ciphertext, p, q, e):
     n = p * q
     phi = (p - 1) * (q - 1)
     d = modinvrsa(e, phi)
    
     message = pow(ciphertext, d, n)
     return message

@app.route('/rsa', methods=['GET', 'POST'])
def rsa():
     if request.method == 'POST':
             # Get user input from the form
         p = int(request.form['p'])
         q = int(request.form['q'])
         e = int(request.form['e'])
         message = int(request.form['message'])
         action=request.form['action']
         if action == 'chiffrement' or action == 'dechiffrement':
             if action == 'chiffrement':
                 result = encryptRsa(message, p, q, e)
             elif action == 'dechiffrement':
                 result= decryptRsa(message, p, q, e)

             return render_template('rsa.html',  result=result)

         else:
             return "Action non reconnue."

     return render_template('rsa.html', resultat=None)
######################################################################################


#######################################__DES_################################################
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def generate_des_key():
    # Générer une clé DES de 56 bits (7 octets)
    return get_random_bytes(7) + b'\x00'


def hex_to_binary(hex_str):
    # Convertir une chaîne hexadécimale en une chaîne binaire
    return bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)


def encrypt_des(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode('utf-8'), 8)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def decrypt_des(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(ciphertext), 8)
    return decrypted_text.decode('utf-8')


@app.route('/des', methods=['GET', 'POST'])
def des():
    if request.method == 'POST':
        texte = request.form['texte']
        action = request.form['action']
        des_key_hex = request.form['des_key']

        try:
            # Convertir la clé hexadécimale en une séquence d'octets
            des_key = bytes.fromhex(des_key_hex)
        except ValueError:
            return "Clé non valide (format hexadécimal incorrect)."

        if len(des_key) != 8:
            return "La clé doit être de 8 octets (16 caractères hexadécimaux)."

        if action == 'encryption':
            ciphertext = encrypt_des(texte, des_key)
            return render_template('des.html', resultat=ciphertext.hex(), action=action, des_key=des_key_hex)
        elif action == 'decryption':
            decrypted_text = decrypt_des(bytes.fromhex(texte), des_key)
            return render_template('des.html', resultat=decrypted_text, action=action, des_key=des_key_hex)
        else:
            return "Action non reconnue."

    return render_template('des.html', resultat=None, action=None, des_key=None)






################################################################################################################


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        action = request.form['action']

        if action == 'cesar':
            return render_template('cesar.html', action=action)
        elif action == 'multiplication':
            return render_template('multiplication.html', action=action)
        elif action == 'affine':
            return render_template('affine.html', action=action)
        elif action == 'vigenere':
            return render_template('vigenere.html', action=action)
        elif action == 'hill':
            return render_template('hill.html', action=action)
        elif action == 'transposition':
            return render_template('transposition.html', action=action)
        elif action == 'transposition_simple':
            return render_template('transposition_simple.html', action=action)
        elif action == 'permutation':
            return render_template('permutation.html', action=action)
        elif action == 'aes':
            return render_template('aes.html', action=action)
        elif action == 'rcc4':
            return render_template('rcc4.html', action=action)
        elif action == 'rsa':
            return render_template('rsa.html', action=action)
        elif action == 'des':
            return render_template('des.html', action=action)
        else:
            resultat = "Action non reconnue."
            return render_template('index.html', resultat=resultat, action=action)

    return render_template('index.html', resultat=None)


if __name__ == '__main__':
    app.run(debug=True)
