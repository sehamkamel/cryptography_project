from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QComboBox,
    QPushButton,
    QFrame,
    QSpacerItem,
    QSizePolicy,
    QHBoxLayout,
    QListView,
    QTextEdit,
)
from PyQt5.QtGui import QTextCursor
from PyQt5.QtWidgets import QStackedWidget
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPalette, QColor
import sys
from Algorithms.rail_fence import rail_fence_encrypt, rail_fence_decrypt
from Algorithms.DES_keygen import des_key_generation, validate_des_key
from Algorithms.onetimepad import onetimepad_encrypt, onetimepad_decrypt
from Algorithms.RSA import generate_keys, rsa_encrypt, rsa_decrypt


# ---------------------------- UI CLASS ----------------------------
class EncryptionUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Encryption/ Decryption Tool")
        self.rsa_public_key = None
        self.rsa_private_key = None


        # --- Theme Definitions ---
        self.LIGHT_THEME = {
    "main_bg": "#0F172A",
    "frame_bg": ["#B3E5FC", "#C8E6C9", "#FFF9C4", "#FFCDD2", "#E1BEE7", "#B2DFDB"],  # 6 ألوان الآن
    "label_color": "#333333",
    "input_bg": "white",
    "input_text": "black",
    "button_bg": "#6A0DFF",
    "button_hover": "#7C25FF",
    "toggle_text": "Dark Mode",
}
        self.DARK_THEME = {
    "main_bg": "#1E1E1E",
    "frame_bg": ["#3A3A3A", "#4A4A4A", "#5A5A5A", "#6A6A6A", "#7A7A7A", "#8A8A8A"],  # 6 ألوان
    "label_color": "#FFFFFF",
    "input_bg": "#2C2C2C",
    "input_text": "#FFFFFF",
    "button_bg": "#007ACC",
    "button_hover": "#0099E6",
    "toggle_text": "Light Mode",
}

        self.current_theme = self.LIGHT_THEME

        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)

        # --- Title ---
        self.title_label = QLabel("Cryptography")
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setStyleSheet(
            "font-size: 32px; font-weight: bold; color: white;"
        )

        # --- Toggle Button ---
        self.toggle_button = QPushButton(self.current_theme["toggle_text"])
        self.toggle_button.setFixedHeight(35)
        self.toggle_button.setFixedWidth(100)
        self.toggle_button.clicked.connect(self.toggle_theme)

        header_layout = QHBoxLayout()
        header_layout.addWidget(self.title_label)
        header_layout.addWidget(self.toggle_button)
        main_layout.addLayout(header_layout)
        main_layout.addSpacing(20)

        # --- Section builder ---
        self.frames = []

        def create_section(title, widget, index):
            frame = QFrame()
            frame.setProperty("frame_index", index)
            layout = QVBoxLayout()
            layout.setContentsMargins(15, 10, 15, 10)
            label = QLabel(title)
            label.setProperty("label_type", "frame_title")
            layout.addWidget(label)
            layout.addWidget(widget)
            frame.setLayout(layout)
            self.frames.append(frame)
            return frame

        # --- Inputs ---
        self.message_input = QLineEdit()
        sec_msg = create_section("Message", self.message_input, 0)

        self.key_input = QLineEdit()
        sec_key = create_section("Key", self.key_input, 1)

        self.method_box = QComboBox()
        self.method_box.addItems(
            ["Multiplicative", "One Time Pad", "Rail Fence", "RSA", "AES", "DES"]
        )
        list_view = QListView()
        list_view.setStyleSheet(
            
            """
            background-color: #F7E7CE;
            color: black;
            selection-background-color: #EAD6C3;
            border-radius: 0px;
        """
        )
        self.method_box.setView(list_view)
        sec_method = create_section("Method", self.method_box, 2)
        self.method_box.currentTextChanged.connect(self.method_changed)

        self.result_box = QTextEdit()  # <-- Changed from QLineEdit to QTextEdit
        self.result_box.setReadOnly(True)
        self.result_box.setFixedHeight(180)
        sec_result = create_section("Result", self.result_box, 3)
        # --- RSA specific inputs ---
        self.p_input = QLineEdit()
        self.q_input = QLineEdit()

        sec_p = create_section("Prime p", self.p_input, 4)
        sec_q = create_section("Prime q", self.q_input, 5)


        # --- Buttons ---
        self.btn_encrypt = QPushButton("Encrypt")
        self.btn_decrypt = QPushButton("Decrypt")
        self.btn_generate_des = QPushButton("Generate DES Keys")

        for b in (self.btn_encrypt, self.btn_decrypt, self.btn_generate_des):
            b.setFixedHeight(45)
            b.setProperty("button_type", "action")
            b.setStyleSheet(
                """
                QPushButton {
                    background-color: #F7E7CE;
                    color: black;
                    border-radius: 22px;
                    font-size: 16px;
                    font-weight: bold;
                }
                QPushButton:hover { background-color: #EAD6C3; }
            """
            )

        self.btn_encrypt.clicked.connect(self.encrypt_action)
        self.btn_decrypt.clicked.connect(self.decrypt_action)
        self.btn_generate_des.clicked.connect(self.generate_des_keys)
        self.btn_generate_des.hide()

        self.btn_generate_rsa = QPushButton("Generate RSA Keys")
        self.btn_generate_rsa.setFixedHeight(45)
        self.btn_generate_rsa.setStyleSheet(
    """
    QPushButton {
        background-color: #F7E7CE;
        color: black;
        border-radius: 22px;
        font-size: 16px;
        font-weight: bold;
    }
    QPushButton:hover { background-color: #EAD6C3; }
"""
)
        self.btn_generate_rsa.clicked.connect(self.generate_rsa_keys)  # هنضيف الدالة بعد كده
         # بعد إنشاء self.p_input و self.q_input وsec_p و sec_q
        self.frames[4].hide()            # Prime p مخفي افتراضياً
        self.frames[5].hide()            # Prime q مخفي افتراضياً
        self.btn_generate_rsa.hide()     # زر Generate RSA مخفي افتراضياً

# ترتيب إضافة العناصر للواجهة
        main_layout.addWidget(sec_method)
        main_layout.addWidget(sec_msg)
        main_layout.addWidget(sec_key)
        main_layout.addWidget(sec_result)
        main_layout.addWidget(sec_p)
        main_layout.addWidget(sec_q)
        main_layout.addWidget(self.btn_generate_rsa)  # مكان ثابت الآن
        main_layout.addWidget(self.btn_encrypt)
        main_layout.addWidget(self.btn_decrypt)
        main_layout.addWidget(self.btn_generate_des)
        main_layout.addStretch(1)


        self.setLayout(main_layout)
        self.resize(380, 700)
        self.apply_theme(self.current_theme)

    # ---------------- THEME LOGIC ----------------
    def apply_theme(self, theme):
        self.setStyleSheet(f"background-color: {theme['main_bg']};")
        self.title_label.setStyleSheet(
            f"font-size: 32px; font-weight: bold; color: white;"
        )
        for frame in self.frames:
            index = frame.property("frame_index")
            frame_color = theme["frame_bg"][index]
            frame.setStyleSheet(
                f"""
                QFrame {{
                    background-color: {frame_color};
                    border-radius: 35px;
                }}
                QLabel {{
                    color: {theme['label_color']};
                    font-size: 17px;
                    font-weight: bold;
                    padding-left: 10px;
                }}
                QLineEdit {{
                    background: {theme['input_bg']};
                    color: {theme['input_text']};
                    border-radius: 15px;
                    padding: 8px;
                    font-size: 20px;
                }}
                QTextEdit {{
                    background: {theme['input_bg']};
                    color: {theme['input_text']};
                    border-radius: 15px;
                    padding: 8px;
                    font-size: 16px;
                }}
                QComboBox {{
                    background: {theme['input_bg']};
                    color: {theme['input_text']};
                    border-radius: 15px;
                    padding: 3px;
                    font-size: 14px;
                }}
            """
            )

        self.toggle_button.setText(theme["toggle_text"])
        self.toggle_button.setStyleSheet(
            """
            QPushButton {
                background-color: #F7E7CE;
                color: black;
                border-radius: 17px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #EAD6C3; }
        """
        )

    def toggle_theme(self):
        self.current_theme = (
            self.DARK_THEME
            if self.current_theme == self.LIGHT_THEME
            else self.LIGHT_THEME
        )
        self.apply_theme(self.current_theme)

    # ---------------- ACTIONS ----------------
    # ---------------- Rail Fence ----------------
    def encrypt_action(self):
        msg = self.message_input.text()
        key = self.key_input.text()
        method = self.method_box.currentText()
        try:
            if method == "Rail Fence":
                rails = int(key)
                if rails <= 1 or rails > len(msg):
                    output = "Key must be between 2 and message length"
                else:
                    output = rail_fence_encrypt(msg, rails)
            else:
                output = "Not Implemented"
            self.result_box.setText(output)
        except Exception:
            self.result_box.setText("Invalid Key")

    def decrypt_action(self):
        msg = self.result_box.toPlainText()
        key = self.key_input.text()
        method = self.method_box.currentText()
        try:
            if method == "Rail Fence":
                rails = int(key)
                if rails <= 1 or rails > len(msg):
                    output = "Key must be between 2 and message length"
                else:
                    output = rail_fence_decrypt(msg, rails)
            else:
                output = "Not Implemented"
            self.result_box.setText(output)
        except Exception:
            self.result_box.setText("Invalid Key")

    def method_changed(self, method):
    # مسح كل الحقول عند تغيير الطريقة
        self.message_input.clear()
        self.key_input.clear()
        self.result_box.clear()

    # ---------------- DES ----------------
        if method == "DES":
           self.message_input.hide() 
           self.frames[1].show()
           self.frames[0].hide()           # Frame الرسالة
           self.btn_encrypt.hide()
           self.btn_decrypt.hide()
           self.btn_generate_des.show()
           self.frames[4].hide()           # Prime p
           self.frames[5].hide()           # Prime q
           self.btn_generate_rsa.hide()

    # ---------------- RSA ----------------
        elif method == "RSA":
           self.message_input.show()
           self.message_input.setReadOnly(False)
           self.frames[0].show()
       
           self.frames[4].show()           # Prime p
           self.frames[5].show()           # Prime q
           self.frames[1].hide()           # Key input غير مستخدم
           self.btn_generate_rsa.show()
           self.btn_encrypt.show()
           self.btn_decrypt.show()
           self.btn_generate_des.hide()

    # ---------------- Other methods ----------------
        else:
           self.message_input.show()
           self.message_input.setReadOnly(False)  # السماح بالكتابة
           self.frames[0].show()
           self.frames[1].show()           # Key
           self.frames[4].hide()           # Prime p
           self.frames[5].hide()           # Prime q
           self.btn_generate_rsa.hide()
           self.btn_generate_des.hide()
           self.btn_encrypt.show()
           self.btn_decrypt.show()


    

    def generate_des_keys(self):
        key = self.key_input.text().strip()
        self.result_box.clear()
        if not key:
            self.result_box.setText("Please enter a DES key!")
            return
        if validate_des_key(key) is None:
            self.result_box.setText(
                "Invalid DES key! Must be 16 hex digits or 64-bit binary."
            )
            return
        try:
            keys = des_key_generation(key)
        except Exception as e:
            self.result_box.setText(f"Error: {str(e)}")
            return
        text = "🔑 Round Keys:\n"
        for i, k in enumerate(keys, start=1):
            text += f"Round {i}: {k}\n"
        self.result_box.setText(text)
        self.result_box.moveCursor(QTextCursor.Start)  # Scroll to top

    
    def generate_rsa_keys(self):
        self.result_box.clear()
        try:
            p = int(self.p_input.text())
            q = int(self.q_input.text())
        except ValueError:
           self.result_box.setText("⚠️ Enter valid integers for p and q!")
           return

        try:
        # استدعاء الدالة generate_keys من كود RSA
            public_key, private_key = generate_keys(p, q)
            e, n = public_key
            d, n_private = private_key

        # حفظ المفاتيح في المتغيرات الخاصة بالكلاس لاستخدامها لاحقًا
            self.rsa_public_key = public_key
            self.rsa_private_key = private_key

        # إنشاء نص العرض للمفاتيح
            text = (
            f"🔑 RSA Keys Generated:\n\n"
            f"Public Key (e, n): ({e}, {n})\n"
            f"Private Key (d, n): ({d}, {n_private})"
        )

        # عرض النص في صندوق النتيجة
            self.result_box.setText(text)
            self.result_box.moveCursor(QTextCursor.Start)  # الرجوع للبداية
        except Exception as ex:
            self.result_box.setText(f"Error generating keys: {str(ex)}")
 


        



    # ---------------- eccrypt & decrypt ----------------
    def encrypt_action(self):
       msg = self.message_input.text()
       key = self.key_input.text()
       method = self.method_box.currentText()
       try:
        if method == "Rail Fence":
            rails = int(key)
            if rails <= 1 or rails > len(msg):
                output = "Key must be between 2 and message length"
            else:
                output = rail_fence_encrypt(msg, rails)

        elif method == "One Time Pad":
            if msg == "":
                output = "⚠️ Enter a message first!"
            elif key == "":
                output = "⚠️ Enter a key for OTP!"
            else:
                output = onetimepad_encrypt(msg, key)

        elif method == "RSA":
            if not hasattr(self, "rsa_public_key"):
                output = "⚠️ Generate RSA keys first!"
            elif msg == "":
                output = "⚠️ Enter a message first!"
            else:
                output = rsa_encrypt(msg, self.rsa_public_key)

        else:
            output = "Not Implemented"

        self.result_box.setText(output)
       except Exception as e:
        self.result_box.setText(f"Invalid Key or Error: {str(e)}")


    def decrypt_action(self):
       msg = self.result_box.toPlainText()
       key = self.key_input.text()
       method = self.method_box.currentText()
       try:
        if method == "Rail Fence":
            rails = int(key)
            if rails <= 1 or rails > len(msg):
                output = "Key must be between 2 and message length"
            else:
                output = rail_fence_decrypt(msg, rails)

        elif method == "One Time Pad":
            if msg == "":
                output = "⚠️ Enter a message first!"
            elif key == "":
                output = "⚠️ Enter a key for OTP!"
            else:
                output = onetimepad_decrypt(msg, key)

        elif method == "RSA":
            if not hasattr(self, "rsa_private_key"):
                output = "⚠️ Generate RSA keys first!"
            elif msg == "":
                output = "⚠️ Enter a message first!"
            else:
                output = rsa_decrypt(msg, self.rsa_private_key)

        else:
            output = "Not Implemented"

        self.result_box.setText(output)
       except Exception as e:
        self.result_box.setText(f"Invalid Key or Error: {str(e)}")


    # ---------------- AES ----------------
    # ---------------- Multiplicative ----------------
  


# ---------------- MAIN ----------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EncryptionUI()
    window.show()
    sys.exit(app.exec_())
