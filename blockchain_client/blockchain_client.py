import binascii
import Crypto
import Crypto.Random
import json
import os
import requests
import urllib.request
# from dotenv.main import load_dotenv
from twilio.rest import Client
from datetime import date, timedelta
from flask import Flask, request, jsonify, render_template, redirect
from flask_cors import CORS
from collections import OrderedDict, defaultdict
# from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import random
import smtplib
from flask import *


#twilio configs
account_sid = 'ACce01f251c44e2dbc1aa5156f6f1e6185'
auth_token = '1df67e9324d10c38f801acf39e639e19'
service = 'VAabccc67d5191c56bd0bf5c3cf3f8ea3c'

client = Client(account_sid, auth_token)

def generateOTP(otp_size = 6):
    final_otp = ''
    for i in range(otp_size):
        final_otp = final_otp + str(random.randint(0,9))
    return final_otp

def sendEmailVerificationRequest(sender="rice.supplychain.verify@gmail.com",receiver="chandru.satchi@gmail.com", custom_text="Hello, Your OTP is "):
    server = smtplib.SMTP('smtp.gmail.com',587)
    server.starttls()
    google_app_password = "Maheraja"
    server.login(sender,google_app_password)
    cur_otp = generateOTP()
    msg = custom_text +  cur_otp
    server.sendmail(sender,receiver,msg)
    server.quit()
    return cur_otp

class Transaction:

    def __init__(self, sender_public_key, sender_private_key, receipient_public_key, amount):
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key
        self.receipient_public_key = receipient_public_key
        self.amount = amount

    def to_dict(self):
        return OrderedDict({
            'sender_public_key': self.sender_public_key,
            'recipient_public_key': self.receipient_public_key,
            'amount': self.amount
        })

    def sign_transaction(self):
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        hash = SHA.new(str(self.to_dict()).encode('utf8'))
        signature = binascii.hexlify(signer.sign(hash)).decode('ascii')
        return signature


app = Flask(__name__)
app.secret_key = 'EmailAuthenticationByCRAG2021'

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/register/producer')
def register_producer():
    return render_template('producer_reg.html')

@app.route('/wallet')
def wallet():
    return render_template('index.html', data = session['temp_dict'])

@app.route('/signup', methods=['POST'])
def submit():
    name=request.form['name']
    kishan_id = request.form['kishan_id']
    aadhaar_no = request.form['aad_no']
    email = request.form['email']
    phone =request.form['phone_no']
    #Check
    print("Recieved Inp: ",name,kishan_id,aadhaar_no,email,phone)

    #Sending OTP to Mobile
    verification = client.verify \
                     .services(service) \
                     .verifications \
                     .create(to=phone, channel='sms')
    
    #Sending OTP to Mail
    mail_otp = sendEmailVerificationRequest(receiver=email)

    print("Sent OTP: ",mail_otp)
    print("Phone Verification Status: ",verification.status)

    session['current_otp'] = mail_otp
    session['phone_num'] = phone
    session['name'] = name
    session['id'] = kishan_id
    session['aadhar'] = aadhaar_no
    session['email'] = email

    session['temp_dict'] = {
        'name' : session['phone_num'],
        'id' : session['id'],
        'aadhar': session['aadhar'],
        'email': session['email'],
        'phone': session['phone_num'] 
    }

    response = {'email': email,
                'phone': phone,
                'status':verification.status,
                'mail_otp': mail_otp}
    
    return response, 200

@app.route('/verify/otp', methods=['POST'])
def verify_otp():
    phone_otp = request.form['phone_otp']
    email_otp = request.form['email_otp']
    current_phone_number =  session['phone_num']
    current_user_email_otp = session['current_otp']
    print(f"OTPs Recieved from user: M:{phone_otp}, E:{email_otp}")

    #Verifiying Mobile OTP - Twilio and Email OTP stored in current_user_email_otp
    verification = client.verify \
        .services(service) \
        .verification_checks \
        .create(to=current_phone_number, code=phone_otp)
    print(f'Post Verification status: {verification.status}')

    if int(current_user_email_otp) == int(email_otp) and verification.status == 'approved':
        response = {
            'status_email': 1,
            'status_phone': 1
        }
        return jsonify(response), 200
    else:
        response = {
            'message': 'Invalid OTPs'
        }
        return jsonify(response), 403

@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    sender_public_key = request.form['sender_public_key']
    sender_private_key = request.form['sender_private_key']
    recipient_public_key = request.form['recipient_public_key']
    amount = request.form['amount']

    transaction = Transaction(sender_public_key, sender_private_key, recipient_public_key, amount)
    response = {
        'transaction': transaction.to_dict(),
        'signature': transaction.sign_transaction(),
    }

    return jsonify(response), 200

# @app.route('/signup')
# def signup():
#     return render_template('producer_reg.html')

@app.route('/make/transaction')
def make_transaction():
    return render_template('make_transaction.html')


@app.route('/view/transactions')
def view_transactions():
    return render_template('view_transactions.html')


@app.route('/wallet/new')
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    
    response = {
        'private_key': binascii.hexlify(private_key.export_key(format("DER"))).decode('ascii'),
        'public_key': binascii.hexlify(public_key.export_key(format("DER"))).decode('ascii')
    }
    return jsonify(response)


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8081, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
