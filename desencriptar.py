import tkinter as tk
from tkinter import ttk
from cryptography.fernet import Fernet
def cargar_clave():
    with open("clave.txt", "rb") as f:
        clave = f.read()
    return clave

def desencriptar_frase():
    try:
        clave = cargar_clave()
        cipher_suite = Fernet(clave)
        with open("frase_encriptada.txt", "rb") as f:
            frase_encriptada = f.read()
        frase_desencriptada = cipher_suite.decrypt(frase_encriptada)
        texto_final = frase_desencriptada.decode('utf-8')
        info_frase_entry.delete(1.0, tk.END)  # Limpiar el campo de texto
        info_frase_entry.insert(tk.END, f"Texto desencriptado:\n{texto_final}\n")
    except FileNotFoundError:
        info_frase_entry.delete(1.0, tk.END)  # Limpiar el campo de texto
        info_frase_entry.insert(tk.END, "No se encontró el archivo de texto encriptado.\n")
    except Exception as e:
        info_frase_entry.delete(1.0, tk.END)  # Limpiar el campo de texto
        info_frase_entry.insert(tk.END, f"Error al desencriptar la frase: {e}\n")
root = tk.Tk()
root.title("Desencriptar Frase")
root.geometry("400x300")
root.resizable(False, False)
padding_y = 10
link_label = tk.Label(root, text="Ingrese el archivo de texto encriptado:", bg="yellow", fg="black")
link_label.pack(pady=padding_y)
link_entry = tk.Entry(root, bg="#FFFFFF", width=50)
link_entry.pack(pady=padding_y)
style = ttk.Style()
style.configure('Custom.TButton', foreground="white", background="#333333", font=("Helvetica", 12))
decrypt_button = ttk.Button(root, text="Desencriptar Frase", style='Custom.TButton', command=desencriptar_frase)
decrypt_button.pack(pady=padding_y)
info_frase_entry = tk.Text(root, bg="#FFFFFF", width=50, height=6)
info_frase_entry.pack(pady=padding_y)
root.mainloop()
