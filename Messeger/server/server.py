import time
import socket
import base64
import threading


class Server:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.all_client = []
        
        # Запускаем прослушивание соединений
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.ip, self.port))
        self.server.listen(0)
        threading.Thread(target=self.connect_handler).start()
        print('Сервер запущен!')
        

    # Обрабатываем входящие соединения
    def connect_handler(self):
        while True:
            client, address = self.server.accept()
            if client not in self.all_client:
                self.all_client.append(client)
                threading.Thread(target=self.message_handler, args=(client,)).start()
                client.send('Успешное подключение к чату!'.encode('utf-8'))
            time.sleep(1)


    # Обрабатываем отправленный текст
    def message_handler(self, client_socket):
        while True:
            message = client_socket.recv(1024)
            print(message)

            # Удаляем текущий сокет
            if message == b'exit':
                self.all_client.remove(client_socket)
                break

            for client in self.all_client:
                if client != client_socket:
                    client.send(message)
            time.sleep(1)
            


myserver = Server('127.0.0.1', 5555)