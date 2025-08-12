import socket
import sys
from threading import Thread
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QVBoxLayout, QPushButton, QComboBox, QHBoxLayout, QMessageBox
)
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt, QSize
import screeninfo

def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

class ViewerWindow(QMainWindow):
    def __init__(self, conn):
        super().__init__()
        self.conn = conn
        self.setWindowTitle("Remote Viewer")
        self.resize(1280, 720)

        self.label = QLabel(self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setMinimumSize(640, 360)

        
        self.fps = 10  
        self.fps_label = QLabel(f"FPS: {self.fps}")
        btn_fps_up = QPushButton("FPS +")
        btn_fps_down = QPushButton("FPS -")
        btn_fps_up.clicked.connect(self.increase_fps)
        btn_fps_down.clicked.connect(self.decrease_fps)

        
        self.monitor_combo = QComboBox()
        self.monitors = screeninfo.get_monitors()
        for i, mon in enumerate(self.monitors):
            self.monitor_combo.addItem(f"Monitor {i+1}: {mon.width}x{mon.height}")
        self.monitor_combo.currentIndexChanged.connect(self.change_monitor)

        
        controls_layout = QHBoxLayout()
        controls_layout.addWidget(btn_fps_down)
        controls_layout.addWidget(self.fps_label)
        controls_layout.addWidget(btn_fps_up)
        controls_layout.addStretch()
        controls_layout.addWidget(self.monitor_combo)

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.label)
        main_layout.addLayout(controls_layout)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        self.recv_thread = Thread(target=self.receive_frames, daemon=True)
        self.recv_thread.start()

        
        self.current_monitor_index = 0

        
        self.send_monitor_index()

    def send_monitor_index(self):
        try:
            
            data = self.current_monitor_index.to_bytes(1, 'big')
            self.conn.sendall(b'MNIT' + len(data).to_bytes(4, 'big') + data)
        except Exception as e:
            print(f"Error sending monitor index: {e}")

    def change_monitor(self, index):
        self.current_monitor_index = index
        self.send_monitor_index()

    def increase_fps(self):
        if self.fps < 30:
            self.fps += 1
            self.fps_label.setText(f"FPS: {self.fps}")
            self.send_fps()

    def decrease_fps(self):
        if self.fps > 1:
            self.fps -= 1
            self.fps_label.setText(f"FPS: {self.fps}")
            self.send_fps()

    def send_fps(self):
        try:
            data = self.fps.to_bytes(1, 'big')
            self.conn.sendall(b'FPSC' + len(data).to_bytes(4, 'big') + data)
        except Exception as e:
            print(f"Error sending FPS: {e}")

    def receive_frames(self):
        try:
            while True:
                header = recvall(self.conn, 4)
                if not header:
                    break
                if header == b'IMG ':
                    length = int.from_bytes(recvall(self.conn, 4), 'big')
                    img_data = recvall(self.conn, length)
                    if img_data:
                        pixmap = QPixmap()
                        pixmap.loadFromData(img_data)
                        self.label.setPixmap(
                            pixmap.scaled(
                                self.label.size(),
                                Qt.KeepAspectRatio,
                                Qt.SmoothTransformation
                            )
                        )
        except Exception as e:
            print(f"[Viewer] Disconnected: {e}")
        finally:
            self.conn.close()

def main():
    app = QApplication(sys.argv)

    ip = input("Enter IP to bind (e.g. 0.0.0.0): ").strip()
    port_str = input("Enter port to bind (e.g. 4444): ").strip()

    if not ip or not port_str.isdigit():
        print("Invalid IP or port.")
        sys.exit()

    port = int(port_str)

    listener = socket.socket()
    try:
        listener.bind((ip, port))
        listener.listen(1)
        print(f"[SERVER] Listening on {ip}:{port}")
        conn, addr = listener.accept()
        print(f"[SERVER] Connection from {addr}")

        viewer = ViewerWindow(conn)
        viewer.show()

        sys.exit(app.exec())
    except Exception as e:
        print(f"[SERVER ERROR]: {e}")
        sys.exit()

if __name__ == "__main__":
    main()
