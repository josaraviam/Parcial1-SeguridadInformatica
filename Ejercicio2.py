import os
import qrcode
import tempfile
import textwrap
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

# ---------------------- Funciones de Seguridad ----------------------

def generar_claves():
    """Genera un par de claves RSA (privada y pública)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    print("\n✅ Claves RSA generadas correctamente.")
    return private_key, public_key

def calcular_hash_pdf(pdf_path):
    """Calcula el hash SHA-256 de un documento PDF."""
    try:
        with open(pdf_path, "rb") as f:
            contenido = f.read()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(contenido)
        hash_result = digest.finalize()
        print(f"\n✅ Hash del documento calculado: {hash_result.hex()}")
        return hash_result
    except FileNotFoundError:
        print(f"\n❌ Error: No se encontró el archivo {pdf_path}.")
        return None

def firmar_hash(hash_documento, private_key):
    """Firma digitalmente un hash con una clave privada RSA."""
    if hash_documento is None:
        print("\n❌ No se puede firmar un hash vacío.")
        return None

    firma = private_key.sign(
        hash_documento,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("\n✅ Documento firmado digitalmente.")
    return firma

def verificar_firma(hash_documento, firma, public_key):
    """Verifica la firma digital con la clave pública correspondiente."""
    if hash_documento is None or firma is None:
        print("\n❌ No se puede verificar una firma inválida.")
        return False

    try:
        public_key.verify(
            firma,
            hash_documento,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("\n✅ Firma verificada correctamente.")
        return True
    except Exception:
        print("\n❌ Error: La firma no es válida.")
        return False

# ---------------------- Función para Generar Código QR ----------------------

def generar_qr(data, filename):
    """Genera un código QR con los datos de la firma y lo guarda como imagen."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4
    )
    qr.add_data(data)
    qr.make(fit=True)
    qr_img = qr.make_image(fill="black", back_color="white")
    qr_path = f"{filename}.png"
    qr_img.save(qr_path)
    return qr_path

# ---------------------- Función para Agregar UNA firma + QR ----------------------

def agregar_firma_y_qr_al_pdf(pdf_path, firma_texto, qr_path, output_path, pos_y_start=150):
    if not pdf_path or not os.path.exists(pdf_path):
        print(f"\n❌ Error: No se encontró el archivo {pdf_path}.")
        return None

    try:
        reader = PdfReader(pdf_path)
        writer = PdfWriter()

        # Crear un PDF temporal seguro
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_file:
            temp_pdf_path = tmp_file.name

        c = canvas.Canvas(temp_pdf_path, pagesize=letter)
        # Fuente pequeña para no estorbar
        c.setFont("Helvetica", 8)

        # Tamaño del QR
        qr_size = 80

        # 1) Dibujar QR a la izquierda
        pos_x_qr = 50
        pos_y_qr = pos_y_start
        c.drawImage(qr_path, pos_x_qr, pos_y_qr, width=qr_size, height=qr_size)

        # 2) Dibujar la firma a la derecha
        #    Empezaremos arriba, al mismo nivel top del QR.
        pos_x_text = pos_x_qr + qr_size + 20  # 20 px de separación
        # El "tope" para el texto
        text_y_top = pos_y_qr + qr_size

        # Preparamos la firma
        wrapped_lines = textwrap.wrap(
            firma_texto,
            width=70,            # Ajusta el ancho de cada línea
            break_long_words=True,
            break_on_hyphens=False
        )

        # Bajamos algo para el título de "FIRMA DIGITAL"
        line_spacing = 10
        c.drawString(pos_x_text, text_y_top, "--- FIRMA DIGITAL ---")
        current_y = text_y_top - 2 * line_spacing

        # Dibujar cada línea de la firma
        for line in wrapped_lines:
            c.drawString(pos_x_text, current_y, line)
            current_y -= line_spacing

        c.showPage()
        c.save()

        # Volvemos a leer el PDF temporal (con la firma y QR)
        temp_pdf_reader = PdfReader(temp_pdf_path)

        # Agregar todas las páginas del PDF original al writer
        for i, page in enumerate(reader.pages):
            if i == len(reader.pages) - 1:
                # Solo fusionamos en la última página
                page.merge_page(temp_pdf_reader.pages[0])
            writer.add_page(page)

        # Guardar el documento PDF resultante
        with open(output_path, "wb") as f:
            writer.write(f)

        # Limpieza del temporal
        if os.path.exists(temp_pdf_path):
            os.remove(temp_pdf_path)

        print(f"\n✅ Bloque de firma + QR agregado: {output_path}")
        return output_path

    except Exception as e:
        print(f"\n❌ Error inesperado al firmar el PDF: {e}")
        return None

# ---------------------- Simulación del Proceso ----------------------

def main():
    pdf_path = "NDA.pdf"
    output_path = "NDA_Signed.pdf"  # Nuevo documento firmado

    # Paso 1: Alice genera claves y firma el documento
    clave_privada_alice, clave_publica_alice = generar_claves()
    hash_documento = calcular_hash_pdf(pdf_path)

    if hash_documento:
        firma_alice = firmar_hash(hash_documento, clave_privada_alice)
        if firma_alice:
            # Convertimos la firma a hex
            firma_alice_hex = firma_alice.hex()
            # Generamos un QR con esa firma
            qr_alice = generar_qr(firma_alice_hex, "qr_alice")

            # Agregar firma de Alice (QR izq, texto der) un poco más arriba
            pdf_firmado = agregar_firma_y_qr_al_pdf(
                pdf_path,
                f"Alice: {firma_alice_hex}",
                qr_alice,
                output_path,
                pos_y_start=200  # <-- Ajusta la altura para no tapar texto
            )

            # Paso 2: La AC verifica la firma de Alice y firma el documento
            if pdf_firmado:  # Verificamos que la primera firma no haya fallado
                clave_privada_ac, clave_publica_ac = generar_claves()
                if verificar_firma(hash_documento, firma_alice, clave_publica_alice):
                    firma_ac = firmar_hash(hash_documento, clave_privada_ac)
                    if firma_ac:
                        firma_ac_hex = firma_ac.hex()
                        qr_ac = generar_qr(firma_ac_hex, "qr_ac")

                        # Agregar firma de la AC más abajo
                        pdf_firmado = agregar_firma_y_qr_al_pdf(
                            pdf_firmado,
                            f"AC: {firma_ac_hex}",
                            qr_ac,
                            output_path,
                            pos_y_start=80  # <-- Otra altura, más abajo
                        )

                        if pdf_firmado:
                            print("\n✅ Documento final firmado por la AC y guardado como NDA_Signed.pdf")
                        else:
                            print("\n❌ Error al agregar la firma de la AC en el PDF.")
                    else:
                        print("\n❌ No se pudo generar la firma de la AC.")
                else:
                    print("\n❌ La firma de Alice no es válida. Proceso detenido.")
            else:
                print("\n❌ Error al agregar la firma de Alice en el PDF.")
        else:
            print("\n❌ Error al firmar el documento con Alice.")
    else:
        print("\n❌ Error al calcular el hash del documento.")

if __name__ == "__main__":
    main()
