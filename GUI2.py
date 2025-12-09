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
# -------------------- AES S-box & helpers --------------------
s_box = [
    [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76],
    [0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0],
    [0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15],
    [0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75],
    [0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84],
    [0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf],
    [0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8],
    [0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2],
    [0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73],
    [0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb],
    [0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79],
    [0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08],
    [0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a],
    [0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e],
    [0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf],
    [0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
]

def hex_to_bytes(hex_str):
    return [int(hex_str[i:i+2],16) for i in range(0,len(hex_str),2)]

def block_to_state(block):
    state = [[0]*4 for _ in range(4)]
    for i in range(16):
        row = i % 4
        col = i // 4
        state[row][col] = block[i]
    return state

def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            byte = state[i][j]
            state[i][j] = s_box[byte>>4][byte&0x0F]
    return state

def shift_rows(state):
    new_state = [row[:] for row in state]
    for i in range(1,4):
        new_state[i] = state[i][i:] + state[i][:i]
    return new_state

def state_to_hex_string(state):
    return ' '.join([f"{b:02X}" for row in state for b in row])

# -------------------- Modify EncryptionUI for AES --------------------
original_encrypt_action = EncryptionUI.encrypt_action
original_method_changed = EncryptionUI.method_changed

def new_method_changed(self, method):
    original_method_changed(self, method)
    if method == "AES":
        self.btn_encrypt.setText("Shift Row")
    else:
        self.btn_encrypt.setText("Encrypt")

def new_encrypt_action(self):
    method = self.method_box.currentText()
    if method == "AES":
        msg = self.message_input.text().strip()
        self.result_box.clear()
        if len(msg) != 32:
            self.result_box.setText("Enter 32 hex characters (16 bytes)!")
            return
        try:
            block = hex_to_bytes(msg)
            state = block_to_state(block)
            state = sub_bytes(state)
            state = shift_rows(state)
            self.result_box.setText(state_to_hex_string(state))
        except Exception as e:
            self.result_box.setText(f"Error: {str(e)}")
    else:
        original_encrypt_action(self)

EncryptionUI.method_changed = new_method_changed
EncryptionUI.encrypt_action = new_encrypt_action
# --------- Extra patch: hide Key field for AES ----------
old_method_changed = EncryptionUI.method_changed

def newer_method_changed(self, method):
    old_method_changed(self, method)

    if method == "AES":
        # اخفاء حقل الـ Key اطار + الإدخال
        self.frames[1].hide()
        self.key_input.hide()
    else:
        # اظهارهم في باقي الخوارزميات
        self.frames[1].show()
        self.key_input.show()
def newer_method_changed(self, method):
    old_method_changed(self, method)

    if method == "AES":
        # اخفاء حقل الـ Key اطار + الإدخال
        self.frames[1].hide()
        self.key_input.hide()
        # اخفاء زرار Decrypt
        self.btn_decrypt.hide()
    else:
        # اظهارهم في باقي الخوارزميات
        self.frames[1].show()
        self.key_input.show()
        self.btn_decrypt.show()  # خلي زرار Decrypt يرجع يظهر

EncryptionUI.method_changed = newer_method_changed

    
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
