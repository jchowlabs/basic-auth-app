## Basic Authentication App

This repository contains a basic implementation of an application that uses passwords, passkeys and biometric recognition. The application illustrates an example of how the registration, enrollment, login and account recovery can look like for general web-application logins. The application is built as a Python Flask application to allow a greater audience to review and understand how these systems work at a high level. 

## Setup

1. Clone the repository to your local computer
2. Create a local Python environment for this application (python3 -m venv basic_auth_app)
3. Activate the environment (source bin/activate)
4. Install the requirements (pip3 install -r requirements.txt)
5. Run the application (python3 basic_auth_app
6. Open browser and navigate to http://127.0.0.1:5000

## Getting Started

1. Create an account on the registration page
2. Login to the account with your email and password
3. Create a Passkey from your Dashboard
4. Logout
5. Login with your Passkey
6. Enroll your face from your Dashboard
7. Logout
8. Login with your face

Note: All sensitive items, including passwords, passkeys and biometric data are stored locally on your machine. Once you are finished using the application, you can simply delete the root project folder from your local computer and any passkeys from your local devices secure enclave. 
