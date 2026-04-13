import socket
import threading
import tkinter as tk
from tkinter import simpledialog

HOST = "127.0.0.1"
PORT = 1234

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


# ---------------- RECEIVE ----------------
def receive():
    while True:
        try:
            message = client.recv(1024).decode('utf-8')

            if message == "USERNAME":
                client.send(username.encode('utf-8'))
	    if "~" in message:
               parts = message.split("~")
               username = parts[0]
               content = parts[1]
               text_area.insert(tk.END, f"[{username}] {content}\n")
        except:
            print("Error")
            client.close()
            break


# ---------------- SEND ----------------
def write():
    message = f"[{username}] {input_area.get()}"
    client.send(message.encode('utf-8'))
    input_area.delete(0, tk.END)


# ---------------- GUI ----------------
root = tk.Tk()
root.withdraw()

username = simpledialog.askstring("Username", "Enter your name")

client.connect((HOST, PORT))

root.deiconify()
root.title("Messenger Client")

text_area = tk.Text(root, height=20, width=50)
text_area.pack()

input_area = tk.Entry(root, width=40)
input_area.pack()

send_button = tk.Button(root, text="Send", command=write)
send_button.pack()

thread = threading.Thread(target=receive)
thread.start()

root.mainloop()