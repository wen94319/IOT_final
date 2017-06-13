#!flask/bin/python
from flask import Flask, request, jsonify
from flask import render_template
from flask_cors import CORS
from webob import Response
import os
import json
import sys
sys.path.append('..')
import aes_ocb

AES = aes_ocb.AES_cipher()
app = Flask('ocb_app')
CORS(app)


@app.route('/', methods=['GET'])
@app.route('/index.html', methods=['GET'])
@app.route('/encrypt.html', methods=['GET'])
def indexInfo():
    return render_template('index.html')


@app.route('/decrypt.html', methods=['GET'])
def decriptInfo():
    return render_template('decrypt.html')


@app.route('/api/ocb/encrypt', methods=['POST'])
def ocb_encryption():
    # Encryption the plaintext
    json_dict = request.get_json()
    plaintext = str(json_dict['plaintext'])
    header = str(json_dict['header'])

    tag, ciphertext = AES.Encrypt(plaintext, header)

    # Ttansform the ciphertext from bytearray to string
    content = {"tag": tag.encode('hex'),
               "ciphertext": ciphertext.encode('hex')}
    body = json.dumps(content)
    return Response(content_type='application/json', body=body)


@app.route('/api/ocb/decrypt', methods=['POST'])
def ocb_decryption():
    # Encryption the plaintext
    json_dict = request.get_json()
    ciphertext = bytearray.fromhex(str(json_dict['ciphertext']))
    header = str(json_dict['header'])
    tag = bytearray.fromhex(str(json_dict['tag']))

    is_authentic, plaintext = AES.Decrypt(ciphertext, header, tag)

    # Ttansform the ciphertext from bytearray to string
    content = {"is_authentic": is_authentic, "plaintext": plaintext}
    body = json.dumps(content)
    return Response(content_type='application/json', body=body)


@app.route('/api/ocb/setkey', methods=['POST'])
def set_key():
    json_dict = request.get_json()
    key = bytearray().fromhex(str(json_dict['key']))
    AES.ocb.setKey(key)
    return Response(content_type='application/json', body="success")


@app.route('/api/ocb/setnonce', methods=['POST'])
def set_nonce():
    json_dict = request.get_json()
    nonce = bytearray().fromhex(str(json_dict['nonce']))
    AES.ocb.nonce = nonce
    return Response(content_type='application/json', body="success")


@app.route('/api/ocb/testcase_Encrypt', methods=['GET'])
def testcase_encryption():
    # Encryption the plaintext
    AES.testcase_Encrypt()
    return Response(content_type='application/json', body="success")


@app.route('/api/ocb/testcase_Correctness', methods=['GET'])
def encryption_correctness():
    # Encryption the plaintext
    AES.testcase_Correctness()
    return Response(content_type='application/json', body="success")


if __name__ == "__main__":
    app.run(host='0.0.0.0', threaded=True)
