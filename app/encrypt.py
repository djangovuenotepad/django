from Crypto.Cipher import DES3
import base64, hashlib


# 单向加密
class HashDate:
    def __init__(self):
        self.salt = "AEFEWAFEAWFAWEFAWFE342342dfafz"

    def hashpd(self, password, jiami):
        try:
            def md5hex(ascii_str):
                return hashlib.md5(ascii_str.encode('ascii')).hexdigest()

            hash2 = md5hex(md5hex(password) + self.salt)
            if str(hash2) == str(jiami):
                return True
            else:
                return False
        except Exception:
            return False

    def hashsc(self, password):
        def md5hex(ascii_str):
            return hashlib.md5(ascii_str.encode('ascii')).hexdigest()

        hash2 = md5hex(md5hex(password) + self.salt)
        return hash2


# 加密解密
class EncryptDate:
    def __init__(self):
        self.key = b"efeafges345fgthg"  # 初始化密钥16位
        self.iv = b'01234567'  # 偏移量
        self.length = DES3.block_size  # 初始化数据块大小
        self.des3 = DES3.new(self.key, DES3.MODE_CBC, self.iv)  # 初始化AES,CBC模式的实例
        # 截断函数，去除填充的字符
        self.unpad = lambda date: date[0:-ord(date[-1])]

    def pad(self, text):
        """
        #填充函数，使被加密数据的字节码长度是block_size的整数倍
        """
        count = len(text.encode('utf-8'))
        add = self.length - (count % self.length)
        entext = text + (chr(add) * add)
        return entext

    def encrypt(self, encrData):  # 加密函数

        res = self.des3.encrypt(self.pad(encrData).encode("utf8"))
        msg = str(base64.b64encode(res), encoding="utf8")
        # msg =  res.hex()
        return msg

    def decrypt(self, decrData):  # 解密函数
        try:
            res = base64.decodebytes(decrData.encode("utf8"))
            # res = bytes.fromhex(decrData)
            msg = self.des3.decrypt(res).decode("utf8")
            return self.unpad(msg)
        except Exception:
            return False


if __name__ == '__main__':
    print(HashDate().hashsc('aaaa'))
    print(HashDate().hashpd('aaaa', '5edbbd80a4b1b180178b2aabd244df76'))
    print(EncryptDate().encrypt('aaaa'))
    print(EncryptDate().decrypt('xz1SyW+jia4='))
