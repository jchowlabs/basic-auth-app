## Basic Authentication App

### Overview

This repository

This repository contains a basic implementation of an application that uses passwords, passkeys and biometric recognition. The application illustrates an example of how the registration, enrollment, login and account recovery can look like for general web-application logins. The application is built as a Python Flask application to allow a greater audience to review and understand how these systems work at a high level. 

### Getting Started

1. Clone the repository to your local computer.
2. Create a local Python environment for this application (python3 -m venv basic_auth_app)
3. Activate the environment (source bin/activate)
4. Install the requirements (pip3 install -r requirements.txt)
5. Run the application (python3 basic_auth_app
6. Open browser and navigate to http://127.0.0.1:5000

### Using Application

1. Sign-up for an account on the home page
2. Add a Passkey, Face and Voice sample
3. Logout
4. Login with Passkey, Face and Voice
5. Try bypassing Face and Voice login with deepfake samples

Note: All sensitive items, including passwords, passkeys and biometric data are stored locally on your device(s). Once you are finished using the application, simply delete the root project folder from your local computer and any Passkeys from your local devices secure enclave. 
