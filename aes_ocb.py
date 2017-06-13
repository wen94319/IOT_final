from ocb.aes import AES
from ocb import OCB
import sys
import time


class AES_cipher:
    def __init__(self):
        self.nonce = bytearray(range(16))
        self.key = bytearray().fromhex('A45F5FDEA5C088D1D7C8BE37CABC8C5C')
        self.aes = AES(128)
        self.ocb = OCB(self.aes)
        self.ocb.setKey(self.key)

    def Encrypt(self, plaintext, header):
        self.ocb.setNonce(self.nonce)
        plaintext = bytearray(plaintext)
        header = bytearray(header)
        (tag, ciphertext) = self.ocb.encrypt(plaintext, header)
        return (str(tag), str(ciphertext))

    def Decrypt(self, ciphertext, header, tag):
        self.ocb.setNonce(self.nonce)
        ciphertext = bytearray(ciphertext)
        header = bytearray(header)
        tag = bytearray(tag)
        (is_authentic, plaintext) = self.ocb.decrypt(header, ciphertext, tag)
        plaintext = plaintext.decode('utf-8')
        return (is_authentic, plaintext)

    def testcase_Encrypt(self):
        # Encrypt Testing
        tStart = time.time()
        self.ocb.setNonce(self.nonce)
        f = open("../testcase/testcase-10KB.txt", 'r')
        content = f.read()
        plaintext = bytearray(content)
        header = bytearray("header")
        (tag, ciphertext) = self.ocb.encrypt(plaintext, header)
        tEnd = time.time()
        print "Encrypt cost %f sec" % (tEnd - tStart)

        # Decrypt Testing
        tStart = time.time()
        self.ocb.setNonce(self.nonce)
        (is_authentic, plaintext) = self.ocb.decrypt(header, ciphertext, tag)
        tEnd = time.time()
        print "Decrypt cost %f sec" % (tEnd - tStart)
        return (tag, ciphertext)

    def testcase_Correctness(self):
        tStart = time.time()
        self.key = bytearray().fromhex('000102030405060708090A0B0C0D0E0F')
        self.nonce = bytearray().fromhex('000102030405060708090A0B0C0D0E0F')
        self.ocb.setKey(self.key)

        header_array = ["", "", "", "", "", "",
                        "0001020304050607",
                        "000102030405060708090A0B0C0D0E0F",
                        "000102030405060708090A0B0C0D0E0F1011121314151617",
                        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627"]
        message_array = ["", "0001020304050607", "000102030405060708090A0B0C0D0E0F",
                         "000102030405060708090A0B0C0D0E0F1011121314151617",
                         "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                         "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
                         "0001020304050607", "000102030405060708090A0B0C0D0E0F",
                         "000102030405060708090A0B0C0D0E0F1011121314151617",
                         "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                         "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627"]
        ciphertext_array = ["", "C636B3A868F429BB", "52E48F5D19FE2D9869F0C4A4B3D2BE57",
                            "F75D6BC8B4DC8D66B836A2B08B32A636CC579E145D323BEB",
                            "F75D6BC8B4DC8D66B836A2B08B32A636CEC3C555037571709DA25E1BB0421A27",
                            "F75D6BC8B4DC8D66B836A2B08B32A6369F1CD3C5228D79FD6C267F5F6AA7B231C7DFB9D59951AE9C",
                            "C636B3A868F429BB", "52E48F5D19FE2D9869F0C4A4B3D2BE57",
                            "F75D6BC8B4DC8D66B836A2B08B32A636CC579E145D323BEB",
                            "F75D6BC8B4DC8D66B836A2B08B32A636CEC3C555037571709DA25E1BB0421A27",
                            "F75D6BC8B4DC8D66B836A2B08B32A6369F1CD3C5228D79FD6C267F5F6AA7B231C7DFB9D59951AE9C"]
        tag_array = ["BF3108130773AD5EC70EC69E7875A7B0", "A45F5FDEA5C088D1D7C8BE37CABC8C5C",
                     "F7EE49AE7AA5B5E6645DB6B3966136F9", "A1A50F822819D6E0A216784AC24AC84C",
                     "09CA6C73F0B5C6C5FD587122D75F2AA3", "9DB0CDF880F73E3E10D4EB3217766688",
                     "8D059589EC3B6AC00CA31624BC3AF2C6", "4DA4391BCAC39D278C7A3F1FD39041E6",
                     "24B9AC3B9574D2202678E439D150F633", "41A977C91D66F62C1E1FC30BC93823CA",
                     "65A92715A028ACD4AE6AFF4BFAA0D396"]

        for i in range(len(header_array)):
            self.ocb.setNonce(self.nonce)
            (tag, ciphertext) = self.ocb.encrypt(bytearray().fromhex(message_array[i]), bytearray().fromhex(header_array[i]))
            if (str(ciphertext).encode('hex').upper() == ciphertext_array[i]) and str(tag).encode('hex').upper() == tag_array[i]:
                print "===== Testcase", (i + 1), " Pass! ====="
            else:
                print "===== Testcase", (i + 1), " Fail! ====="
            print "H : " + header_array[i]
            print "M : " + message_array[i]
            print "C : " + str(ciphertext).encode('hex').upper()
            print "T : " + str(tag).encode('hex').upper()
            print ""
        tEnd = time.time()
        print "Finish the test with %f sec" % (tEnd - tStart)

# if __name__ == '__main__':
#   if len(sys.argv) < 3:
#       print('Usage: \n python final.py <Your Message to be encrypt> <Authencation Associated String>')
#       sys.exit()
#
#   Message = sys.argv[1]
#   Auth = sys.argv[2]
#   test = AES_cipher(Message,Auth);
#   (is_authentic, results) = test.AES_Cypher()
#   print "Is authentic ?: "+ str(is_authentic)
#   print "Decryption : " + results
