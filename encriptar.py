import tkinter as tk
from tkinter import ttk
from cryptography.fernet import Fernet
def encriptar_frase():
    try:
        clave = Fernet.generate_key()
        cipher_suite = Fernet(clave)
        frase = frase_entry.get().encode('utf-8')
        frase_encriptada = cipher_suite.encrypt(frase)
        with open("frase_encriptada.txt", "wb") as f:
            f.write(frase_encriptada)
        with open("clave.txt", "wb") as f:
            f.write(clave)
        info_frase_entry.delete(1.0, tk.END)  # Limpiar el campo de texto
        info_frase_entry.insert(tk.END, "Frase encriptada y clave guardadas en 'frase_encriptada.txt' y 'clave.txt'\n")
    except Exception as e:
        info_frase_entry.delete(1.0, tk.END)  # Limpiar el campo de texto
        info_frase_entry.insert(tk.END, f"Error al encriptar la frase: {e}\n")
root = tk.Tk()
root.title("Encriptar Frase")
root.geometry("400x250")
root.resizable(False, False)
padding_y = 10
frase_label = tk.Label(root, text="Ingrese la frase:", bg="yellow", fg="black")
frase_label.pack(pady=padding_y)
frase_entry = tk.Entry(root, bg="#FFFFFF", width=50)
frase_entry.pack(pady=padding_y)
style = ttk.Style()
style.configure('Custom.TButton', foreground="white", background="#333333", font=("Helvetica", 12))
encrypt_button = ttk.Button(root, text="Encriptar Frase", style='Custom.TButton', command=encriptar_frase)
encrypt_button.pack(pady=padding_y)
info_frase_entry = tk.Text(root, bg="#FFFFFF", width=50, height=4)
info_frase_entry.pack(pady=padding_y)
root.mainloop()
