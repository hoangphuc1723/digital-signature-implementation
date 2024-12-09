import hashlib
from tkinter import Tk, Label, Button, StringVar, Radiobutton, filedialog, messagebox
from PyPDF2 import PdfReader, PdfWriter
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives import hashes

# Generate RSA Keys
def generate_rsa_keys(key_size=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key

# Generate DSA Keys
def generate_dsa_keys(key_size=1024):
    private_key = dsa.generate_private_key(key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key

# Sign PDF
def sign_pdf(input_path, output_path, private_key, algorithm="RSA"):
    reader = PdfReader(input_path)
    writer = PdfWriter()

    # Combine content of all pages for hashing
    content = "".join(page.extract_text() for page in reader.pages)
    content_hash = hashlib.sha256(content.encode()).digest()

    # Sign the hash
    if algorithm == "RSA":
        signature = private_key.sign(
            content_hash,
            PKCS1v15(),
            hashes.SHA256()
        )
    elif algorithm == "DSA":
        signature = private_key.sign(
            content_hash,
            hashes.SHA256()
        )
    else:
        raise ValueError("Unsupported algorithm")

    # Add metadata with signature
    writer.append_pages_from_reader(reader)
    writer.add_metadata({
        "/Signature": signature.hex()
    })

    with open(output_path, "wb") as f:
        writer.write(f)

    return signature.hex(), content_hash.hex()

# Verify PDF
def verify_pdf(input_path, public_key, algorithm="RSA"):
    reader = PdfReader(input_path)

    # Combine content of all pages for hashing
    content = "".join(page.extract_text() for page in reader.pages)
    content_hash = hashlib.sha256(content.encode()).digest()

    # Retrieve the signature from metadata
    metadata = reader.metadata
    signature_hex = metadata.get("/Signature")
    if not signature_hex:
        raise ValueError("No signature found in metadata")
    signature = bytes.fromhex(signature_hex)

    # Verify the signature
    try:
        if algorithm == "RSA":
            public_key.verify(
                signature,
                content_hash,
                PKCS1v15(),
                hashes.SHA256()
            )
        elif algorithm == "DSA":
            public_key.verify(
                signature,
                content_hash,
                hashes.SHA256()
            )
        else:
            raise ValueError("Unsupported algorithm")
        return True, content_hash.hex()
    except Exception as e:
        print(f"Verification failed: {e}")
        return False, content_hash.hex()

# GUI Functions
def select_file():
    file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
    if file_path:
        file_path_var.set(file_path)

def sign_document():
    file_path = file_path_var.get()
    if not file_path:
        messagebox.showerror("Error", "Please select a PDF file")
        return

    output_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
    if not output_path:
        return

    algorithm = algorithm_var.get()
    if algorithm == "RSA":
        signature, content_hash = sign_pdf(file_path, output_path, rsa_private_key, algorithm)
    elif algorithm == "DSA":
        signature, content_hash = sign_pdf(file_path, output_path, dsa_private_key, algorithm)

    status_var.set(f"Signed with {algorithm}\nHash: {content_hash}\nSignature: {signature}")
    messagebox.showinfo("Success", "Document signed successfully!")

def verify_signature():
    file_path = file_path_var.get()
    if not file_path:
        messagebox.showerror("Error", "Please select a PDF file")
        return

    algorithm = algorithm_var.get()
    if algorithm == "RSA":
        valid, content_hash = verify_pdf(file_path, rsa_public_key, algorithm)
    elif algorithm == "DSA":
        valid, content_hash = verify_pdf(file_path, dsa_public_key, algorithm)

    if valid:
        status_var.set(f"Verification Successful\nHash: {content_hash}")
        messagebox.showinfo("Success", "Signature is valid!")
    else:
        status_var.set(f"Verification Failed\nHash: {content_hash}")
        messagebox.showerror("Error", "Signature is invalid!")

# GUI Setup
app = Tk()
app.title("Document Signing and Verification")
app.geometry("400x350")

file_path_var = StringVar()
algorithm_var = StringVar(value="RSA")
status_var = StringVar(value="Ready")

Label(app, text="Select a PDF File:").pack(pady=10)
Button(app, text="Browse", command=select_file).pack()
Label(app, textvariable=file_path_var).pack(pady=5)

Label(app, text="Select Algorithm:").pack(pady=10)
Radiobutton(app, text="RSA", variable=algorithm_var, value="RSA").pack()
Radiobutton(app, text="DSA", variable=algorithm_var, value="DSA").pack()

Button(app, text="Sign Document", command=sign_document).pack(pady=10)
Button(app, text="Verify Signature", command=verify_signature).pack(pady=10)

Label(app, text="Status:").pack(pady=10)
Label(app, textvariable=status_var, fg="blue").pack()

# Generate RSA and DSA keys
rsa_private_key, rsa_public_key = generate_rsa_keys()
dsa_private_key, dsa_public_key = generate_dsa_keys()

app.mainloop()
