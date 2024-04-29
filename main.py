import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import tkinter.messagebox
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import webbrowser
import requests
import psutil
import platform
import subprocess
from cryptography.fernet import Fernet
import os

def guardar_ultima_ruta(ruta):
    with open("ultima_ruta.txt", "w") as file:
        file.write(ruta)

def cargar_ultima_ruta():
    try:
        with open("ultima_ruta.txt", "r") as file:
            return file.readline().strip()
    except FileNotFoundError:
        return ""

def encriptar_link():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    link = link_entry.get().encode('utf-8')
    cipher_text = private_key.public_key().encrypt(
        link,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    var_mac = "00:21:85:76:58:42"
    var_ser = "1386369713"
    if not var_mac or not var_ser:
        info_enlace_entry.insert(tk.END, "Error al obtener la dirección MAC o el número de serie del disco.\n")
        return

    try:
        enlace_desencriptado = private_key.decrypt(
            cipher_text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        texto_desencriptado = desencriptar_frase()
        enlace_final = texto_desencriptado + "/index.php?mac=" + var_mac + "&serie=" + var_ser
        info_enlace_entry.delete('1.0', tk.END)
        info_enlace_entry.insert(tk.END, "Información del enlace:\n")
        info_enlace_entry.insert(tk.END, f"Enlace final: {enlace_final}\n")

        try:
            response = requests.get(enlace_final)
            info_enlace_entry.insert(tk.END, f"Respuesta del servidor:\n{response.text}\n")
            data = response.json()
            var_ip = data.get('url').split('//')[1].split('/')[0]
            var_hash = data.get('hash')
            url_final = f"{var_ip}/sigem/index.php?hash={var_hash}"
            url_final_entry.delete(0, tk.END)
            url_final_entry.insert(0, url_final)

        except requests.exceptions.RequestException as e:
            info_enlace_entry.insert(tk.END, f"Error al obtener la respuesta del servidor: {e}\n")

    except ValueError as e:
        info_enlace_entry.insert(tk.END, f"Error al desencriptar el enlace: {e}\n")

def seleccionar_archivo_bin():
    ruta_archivo = filedialog.askopenfilename(filetypes=[("Archivos binarios", "*.bin")])
    if ruta_archivo:
        try:
            with open(ruta_archivo, 'rb') as file:
                # Intenta leer el archivo binario
                file_content = file.read()
                # Si el contenido del archivo es vacío, muestra un mensaje
                if not file_content:
                    tk.messagebox.showerror("Error", "El archivo binario está vacío o no se puede leer.")
                    return
        except Exception as e:
            tk.messagebox.showerror("Error", f"No se pudo abrir el archivo binario: {e}")
            return
        link_entry.delete(0, tk.END)
        link_entry.insert(0, ruta_archivo)
        guardar_ultima_ruta(ruta_archivo)

def obtener_direccion_mac():
    try:
        for interface, info in psutil.net_if_addrs().items():
            if interface == 'Ethernet':
                for addr in info:
                    if addr.family == psutil.AF_LINK:
                        return addr.address
    except Exception as e:
        print("Error al obtener la dirección MAC:", e)
        return None

def obtener_numero_serie_disco():
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output("wmic diskdrive get serialnumber").decode().strip()
            serial = output.split("\n")[1].strip()
            return serial
        except Exception as e:
            print("Error al obtener el número de serie del disco:", e)
            return None

def desencriptar_frase():
    try:
        clave = cargar_clave()
        cipher_suite = Fernet(clave)
        with open("frase_encriptada.txt", "rb") as f:
            frase_encriptada = f.read()
        frase_desencriptada = cipher_suite.decrypt(frase_encriptada)
        texto_final = frase_desencriptada.decode('utf-8')
        return texto_final  # Devolver la frase desencriptada
    except FileNotFoundError:
        return "Archivo de texto encriptado no encontrado."
    except Exception as e:
        print("Error al desencriptar la frase:", e)
        return "Error al desencriptar la frase."

def cargar_clave():
    with open("clave.txt", "rb") as f:
        clave = f.read()
    return clave

def version1():
    url_final = url_final_entry.get()
    if url_final:
        webbrowser.open(url_final)

def version2():
    url_final = url_final_entry.get()
    if url_final:
        index_sigem = url_final.find("sigem")
        if index_sigem != -1:
            url_final = url_final[:index_sigem + len("sigem")] + "v2" + url_final[index_sigem + len("sigem"):]
        webbrowser.open(url_final)

# Cargar la última ruta seleccionada
ultima_ruta = cargar_ultima_ruta()

root = tk.Tk()
root.title("SIGGE3.0")
root.geometry("400x300")
root.resizable(False, False)
root.configure(bg='yellow')  

padding_y = 10

select_file_button = ttk.Button(root, text="INGRESAR ARCHIVO", style='Custom.TButton', command=seleccionar_archivo_bin)
select_file_button.pack(pady=padding_y)

link_entry = tk.Entry(root, bg="#FFFFFF", width=35)
link_entry.pack(pady=padding_y)
link_entry.insert(0, ultima_ruta)  # Insertar la última ruta seleccionada

style = ttk.Style()
style.configure('Custom.TButton', foreground="white", background="#333333", font=("Helvetica", 12))
encrypt_button = ttk.Button(root, text="INICIAR", style='Custom.TButton', command=encriptar_link)
encrypt_button.pack(pady=padding_y)
info_enlace_entry = tk.Text(root, bg="#FFFFFF", width=50, height=6)
info_enlace_entry.pack_forget()  

url_final_label = tk.Label(root, text="URL Final:", bg="yellow", fg="black")  
url_final_label.pack_forget()  
url_final_entry = tk.Entry(root, bg="#FFFFFF", width=50)
url_final_entry.pack_forget()  

version1_button = tk.Button(root, text="Versión 1", bg="#333333", fg="white", command=version1)
version1_button.pack(pady=5)
version2_button = tk.Button(root, text="Versión 2", bg="#333333", fg="white", command=version2)
version2_button.pack(pady=5)
root.mainloop()
