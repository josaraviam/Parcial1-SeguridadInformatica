from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Función para generar claves RSA
def generar_claves():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    print("\nClaves RSA generadas.")
    return private_key, public_key

# Función para calcular hash SHA-256
def calcular_hash(mensaje):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(mensaje.encode())
    hash_result = digest.finalize()
    print("\nHash calculado:", hash_result.hex())
    return hash_result

# Cifrado RSA
def cifrar_mensaje(mensaje, public_key):
    print("\nIniciando cifrado del mensaje...")
    mensaje_bytes = mensaje.encode()
    partes = [mensaje_bytes[i:i+128] for i in range(0, len(mensaje_bytes), 128)]
    cifrado = []

    for i, parte in enumerate(partes):
        print(f"Cifrando parte {i+1}/{len(partes)}")
        cifrado.append(
            public_key.encrypt(
                parte,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        )
    print("Cifrado completado.")
    return cifrado

# Descifrado RSA
def descifrar_mensaje(cifrado, private_key):
    print("\nIniciando descifrado...")
    descifrado = ""
    for i, parte in enumerate(cifrado):
        print(f"Descifrando parte {i+1}/{len(cifrado)}")
        descifrado += private_key.decrypt(
            parte,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
    print("Descifrado completado.")
    return descifrado

# Ejercicio 1
print("\n--- INICIO DE SIMULACIÓN DEL EJERCICIO 1 ---")
mensaje_original = "A" * 1050  # Mensaje de 1050 caracteres
print("Mensaje original de 1050 caracteres generado. ""\n" "...", mensaje_original)

clave_privada_bob, clave_publica_bob = generar_claves()
cifrado = cifrar_mensaje(mensaje_original, clave_publica_bob)
mensaje_descifrado = descifrar_mensaje(cifrado, clave_privada_bob)

# Verificación del hash
hash_original = calcular_hash(mensaje_original)
hash_descifrado = calcular_hash(mensaje_descifrado)

print("\nComparando hashes...")
print("Mensaje íntegro:", hash_original == hash_descifrado)
print("\n--- FIN DE SIMULACIÓN ---")