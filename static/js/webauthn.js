// WebAuthn functions for passkey operations

// Convert base64url to ArrayBuffer
function base64urlToArrayBuffer(base64url) {
    try {
        // Add padding if needed
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const padding = '='.repeat((4 - base64.length % 4) % 4);
        const base64padded = base64 + padding;
        
        // Decode base64 to binary string
        const binary = window.atob(base64padded);
        
        // Convert binary string to ArrayBuffer
        const buffer = new ArrayBuffer(binary.length);
        const view = new Uint8Array(buffer);
        for (let i = 0; i < binary.length; i++) {
            view[i] = binary.charCodeAt(i);
        }
        return buffer;
    } catch (error) {
        console.error('Error converting base64url to ArrayBuffer:', error);
        throw error;
    }
}

// Convert ArrayBuffer to base64url
function arrayBufferToBase64url(buffer) {
    try {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        const base64 = window.btoa(binary);
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    } catch (error) {
        console.error('Error converting ArrayBuffer to base64url:', error);
        throw error;
    }
}

// Register a new passkey
async function registerPasskey() {
    try {
        // Check if WebAuthn is supported
        if (!window.PublicKeyCredential) {
            alert('WebAuthn is not supported in this browser');
            return;
        }

        console.log('Initiating passkey registration...');
        
        // Get registration options from the server
        const optionsResponse = await fetch('/api/webauthn/register/begin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'same-origin'
        });
        
        if (!optionsResponse.ok) {
            const errorData = await optionsResponse.json();
            throw new Error(errorData.error || 'Failed to get registration options');
        }
        
        const options = await optionsResponse.json();
        console.log('Registration options received:', options);
        
        // Convert challenge from base64url to ArrayBuffer
        options.challenge = base64urlToArrayBuffer(options.challenge);
        
        // Convert user ID directly to plain UTF-8 encoded string
        // This is crucial for Safari compatibility
        const encoder = new TextEncoder();
        options.user.id = encoder.encode(options.user.id);
        
        console.log('Requesting credential creation...');
        
        // Create credential
        const credential = await navigator.credentials.create({
            publicKey: options
        });
        
        console.log('Credential created:', credential);
        
        // Prepare credential data for sending to server
        const credentialData = {
            id: credential.id,
            type: credential.type,
            response: {
                attestationObject: arrayBufferToBase64url(credential.response.attestationObject),
                clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON)
            }
        };
        
        console.log('Sending credential to server...');
        
        // Send credential to server
        const registerResponse = await fetch('/api/webauthn/register/complete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'same-origin',
            body: JSON.stringify(credentialData)
        });
        
        const result = await registerResponse.json();
        
        if (result.success) {
            alert('Passkey registered successfully!');
            location.reload();
        } else {
            alert('Failed to register passkey: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error registering passkey:', error);
        alert('Error registering passkey: ' + error.message);
    }
}

// Authenticate with a passkey
async function authenticateWithPasskey() {
    try {
        // Check if WebAuthn is supported
        if (!window.PublicKeyCredential) {
            alert('WebAuthn is not supported in this browser');
            return;
        }

        console.log('Initiating passkey authentication...');
        
        // Get authentication options from server
        const optionsResponse = await fetch('/api/webauthn/authenticate/begin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'same-origin'
        });
        
        if (!optionsResponse.ok) {
            const errorData = await optionsResponse.json();
            throw new Error(errorData.error || 'Failed to get authentication options');
        }
        
        const options = await optionsResponse.json();
        console.log('Authentication options received:', options);
        
        // Convert challenge from base64url to ArrayBuffer
        options.challenge = base64urlToArrayBuffer(options.challenge);
        
        // Convert allowed credential IDs from base64url to ArrayBuffer
        if (options.allowCredentials) {
            for (let cred of options.allowCredentials) {
                cred.id = base64urlToArrayBuffer(cred.id);
            }
        }
        
        console.log('Requesting credential get...');
        
        // Request credential from authenticator
        const credential = await navigator.credentials.get({
            publicKey: options
        });
        
        console.log('Credential received:', credential);
        
        // Prepare credential data for sending to server
        const authData = {
            id: credential.id,
            type: credential.type,
            response: {
                authenticatorData: arrayBufferToBase64url(credential.response.authenticatorData),
                clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
                signature: arrayBufferToBase64url(credential.response.signature),
                userHandle: credential.response.userHandle ? 
                    arrayBufferToBase64url(credential.response.userHandle) : null
            }
        };
        
        console.log('Sending authentication data to server...');
        
        // Send credential to server for verification
        const authResponse = await fetch('/api/webauthn/authenticate/complete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'same-origin',
            body: JSON.stringify(authData)
        });
        
        const result = await authResponse.json();
        
        if (result.success) {
            console.log('Authentication successful, redirecting...');
            window.location.href = result.redirect;
        } else {
            alert('Authentication failed: ' + (result.error || 'Unknown error'));
        }
        
    } catch (error) {
        console.error('Error during authentication:', error);
        alert('Error during authentication: ' + error.message);
    }
}

// Initialize event listeners
document.addEventListener('DOMContentLoaded', function() {
    console.log('WebAuthn script loaded');
    
    // Add event listener to the "Add Passkey" button
    const addPasskeyBtn = document.getElementById('add-passkey-btn');
    if (addPasskeyBtn) {
        console.log('Passkey registration button found');
        addPasskeyBtn.addEventListener('click', registerPasskey);
    }
    
    // Add event listener to the "Login with Passkey" button on login page
    const loginPasskeyBtn = document.querySelector('.btn-custom-primary[type="button"]');
    if (loginPasskeyBtn) {
        console.log('Passkey authentication button found');
        loginPasskeyBtn.addEventListener('click', authenticateWithPasskey);
    }
});