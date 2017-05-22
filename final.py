from ocb.aes import AES
from ocb import OCB
import sys

class AES_cipher:
  def __init__(self, Message, Auth):
    self.Message = Message
    self.Auth = Auth
    self.en_nonce = bytearray(range(16))
    self.de_nonce = bytearray(range(16))
    self.key = bytearray().fromhex('A45F5FDEA5C088D1D7C8BE37CABC8C5C')
    self.plaintext = bytearray(Message)
    self.header = bytearray(Auth)

  def AES_Cypher(self):
    aes = AES(128)
    ocb = OCB(aes)
    ocb.setKey(self.key)
    ocb.setNonce(self.en_nonce)


    #header2 = bytearray('Recipients: john.doe@example.com')
    (tag,ciphertext) = ocb.encrypt(self.plaintext, self.header)
    ocb.setNonce(self.de_nonce)
    (is_authentic, plaintext2) = ocb.decrypt(self.header, ciphertext, tag)

    return (is_authentic, plaintext2)

if __name__ == '__main__':
  if len(sys.argv) < 3:
      print('Usage: \n python final.py <Your Message to be encrypt> <Authencation Associated String>')
      sys.exit()

  Message = sys.argv[1]
  Auth = sys.argv[2]
  test = AES_cipher(Message,Auth);
  (is_authentic, results) = test.AES_Cypher()
  print "Is authentic ?: "+ str(is_authentic)
  print "Decryption : " + results
