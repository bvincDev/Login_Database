import sys
import bcrypt
import mysql.connector
from config import get_connection

#gui with PySide
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLineEdit, QPushButton,
    QVBoxLayout, QDialog, QFormLayout, QLabel, QMessageBox, QSizePolicy
)
from PySide6.QtGui import QFont


#database table set up
def create_table():
    #create table if one doesn't already exist
    connection = get_connection()
    cursor = connection.cursor()
    create_table_query = """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE,
        email VARCHAR(100) UNIQUE,
        password VARCHAR(100)
    )
    """
    cursor.execute(create_table_query)
    connection.commit()
    cursor.close()
    connection.close()

#after login go to menu
class DashboardWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Dashboard")
        self.setWindowState(Qt.WindowMaximized)
        
        # vertical menu layout
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setAlignment(Qt.AlignCenter)
        
        button_font = QFont("Arial", 16, QFont.Bold)
        
        welcome_label = QLabel("Welcome to Minesweeper")
        welcome_label.setAlignment(Qt.AlignCenter)
        welcome_label.setFont(QFont("Arial", 24, QFont.Bold))  # Increase font size
        layout.addWidget(welcome_label)
        
        
        self.play_button = QPushButton("Play")
        self.play_button.setFont(button_font)
        self.play_button.setFixedSize(250, 60)
        self.play_button.clicked.connect(self.open_play)  # Connect the play button to open_play method
        layout.addWidget(self.play_button, 0, Qt.AlignCenter)
        
        
        self.options_button = QPushButton("Options")
        self.options_button.setFont(button_font)
        self.options_button.setFixedSize(250, 60)  
        layout.addWidget(self.options_button, 0, Qt.AlignCenter)
        
        
        self.leaderboard_button = QPushButton("Leaderboard")
        self.leaderboard_button.setFont(button_font)
        self.leaderboard_button.setFixedSize(250, 60)  
        layout.addWidget(self.leaderboard_button, 0, Qt.AlignCenter)
        
        
        self.quit_button = QPushButton("Quit")
        self.quit_button.setFont(button_font)
        self.quit_button.setFixedSize(250, 60)  
        self.quit_button.setStyleSheet("background-color: red; color: white;")
        layout.addWidget(self.quit_button, 0, Qt.AlignCenter)

    def open_play(self):
        self.play = PlayWindow()
        self.play.show()
        self.close()
    

class RegistrationDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Register")
        self.setModal(True)
        layout = QFormLayout(self)
        
        self.username_edit = QLineEdit()
        layout.addRow("Username:", self.username_edit)
        
        self.email_edit = QLineEdit()
        layout.addRow("Email:", self.email_edit)
        
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        layout.addRow("Password:", self.password_edit)
        
        self.register_button = QPushButton("Register")
        self.register_button.clicked.connect(self.handle_register)
        layout.addRow(self.register_button)
    
    def handle_register(self):
        username = self.username_edit.text().strip()
        email = self.email_edit.text().strip()
        password = self.password_edit.text().strip()
        
        if not username or not email or not password:
            QMessageBox.warning(self, "Input Error", "All fields are required!")
            return
        
        # hash the password using bcrypt
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        try:
            connection = get_connection()
            cursor = connection.cursor()
            insert_query = "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)"
            cursor.execute(insert_query, (username, email, hashed.decode('utf-8')))
            connection.commit()
            QMessageBox.information(self, "Success", "User registered successfully!")
            self.accept()  # clsoe registration dialog
        except mysql.connector.Error as err:
            QMessageBox.warning(self, "Error", f"Error: {err}")
        finally:
            cursor.close()
            connection.close()

#play window
class PlayWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Play")
        self.setWindowState(Qt.WindowMaximized)
        # vertical menu layout
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setAlignment(Qt.AlignCenter)
        
        button_font = QFont("Arial", 16, QFont.Bold)
        
        welcome_label = QLabel("Welcome to Minesweeper")
        welcome_label.setAlignment(Qt.AlignCenter)
        welcome_label.setFont(QFont("Arial", 24, QFont.Bold))  # Increase font size
        layout.addWidget(welcome_label)
        

#login window
class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login")
        self.setGeometry(100, 100, 300, 150)
        
        widget = QWidget()
        self.setCentralWidget(widget)
        layout = QVBoxLayout(widget)
        
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Username")
        layout.addWidget(self.username_edit)
        
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Password")
        self.password_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_edit)
        
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.handle_login)
        layout.addWidget(self.login_button)
        
        self.register_button = QPushButton("Register")
        self.register_button.clicked.connect(self.open_register)
        layout.addWidget(self.register_button)
    
    def handle_login(self):
        username = self.username_edit.text().strip()
        password = self.password_edit.text().strip()
        
        if not username or not password:
            QMessageBox.warning(self, "Input Error", "Please enter both username and password.")
            return
        
        connection = get_connection()
        cursor = connection.cursor()
        query = "SELECT password FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        
        if result is None:
            QMessageBox.warning(self, "Error", "User not found!")
        else:
            stored_password = result[0]
            # verify password using bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                QMessageBox.information(self, "Success", "Login successful!")
                self.open_dashboard()
            else:
                QMessageBox.warning(self, "Error", "Invalid password!")
        
        cursor.close()
        connection.close()

    
    def open_register(self):
        dialog = RegistrationDialog(self)
        dialog.exec()
    
    def open_dashboard(self):
        self.dashboard = DashboardWindow()
        self.dashboard.show()
        self.close()

    



if __name__ == '__main__':
    create_table()  # make sure table exists

    app = QApplication(sys.argv)
    login_window = LoginWindow()
    login_window.show()
    sys.exit(app.exec())
