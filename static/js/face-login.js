document.addEventListener('DOMContentLoaded', function() {
    console.log("Face login script loaded");
    
    const loginFaceBtn = document.getElementById('login-face-btn');
    if (!loginFaceBtn) {
        console.error("Login face button not found");
        return;
    }
    
    loginFaceBtn.addEventListener('click', function() {
        console.log("Login with Face ID button clicked");
        
        // Create modal for face login
        const modal = document.createElement('div');
        modal.className = 'face-login-modal';
        modal.innerHTML = `
            <div class="face-login-content">
                <div class="face-login-header">
                    <h5>Validating Face...</h5>
                    <span class="face-login-close">&times;</span>
                </div>
                <div class="face-login-body">
                    <div class="video-container">
                        <video id="face-login-video" playsinline autoplay></video>
                        <div class="processing-indicator"></div>
                    </div>
                    <div id="face-login-message">Looking for your face...</div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Style the modal
        const style = document.createElement('style');
        style.textContent = `
            .face-login-modal {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background-color: rgba(0,0,0,0.7);
                z-index: 1000;
                display: flex;
                align-items: center;
                justify-content: center;
                animation: fadeIn 0.3s ease-in-out;
            }
            
            .face-login-content {
                background-color: white;
                border-radius: 8px;
                width: 400px;
                max-width: 90%;
                box-shadow: 0 4px 15px rgba(0,0,0,0.2);
                animation: slideIn 0.3s ease-out;
            }
            
            .face-login-header {
                padding: 15px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                border-bottom: 1px solid #eee;
            }
            
            .face-login-close {
                font-size: 28px;
                cursor: pointer;
                transition: color 0.2s;
            }
            
            .face-login-close:hover {
                color: #cc0000;
            }
            
            .face-login-body {
                padding: 20px;
                text-align: center;
            }
            
            .video-container {
                width: 345px; /* 33% bigger than 260px */
                height: 400px; /* Taller than width to create oval */
                border-radius: 50% / 40%; /* Creates oval shape: 50% horizontal radius, 40% vertical */
                overflow: hidden;
                margin: 0 auto;
                border: 3px solid #ddd;
                position: relative;
            }
            
            #face-login-video {
                width: 100%;
                height: 100%;
                object-fit: cover;
            }
            
            #face-login-message {
                margin-top: 15px;
                font-size: 0.9rem;
                min-height: 20px;
            }
            
            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }
            
            @keyframes slideIn {
                from { transform: translateY(-20px); opacity: 0; }
                to { transform: translateY(0); opacity: 1; }
            }
            
            .processing-indicator {
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                width: 60px;
                height: 60px;
                border: 5px solid rgba(255, 255, 255, 0.3);
                border-radius: 50%;
                border-top-color: #fff;
                animation: spin 1s ease-in-out infinite;
                display: none;
            }
            
            @keyframes spin {
                to { transform: translate(-50%, -50%) rotate(360deg); }
            }
        `;
        document.head.appendChild(style);
        
        // Close button functionality
        const closeBtn = modal.querySelector('.face-login-close');
        closeBtn.addEventListener('click', function() {
            stopWebcam();
            modal.remove();
            style.remove();
        });
        
        // Get processing indicator
        const processingIndicator = modal.querySelector('.processing-indicator');
        
        // Start webcam
        const video = document.getElementById('face-login-video');
        let stream = null;
        
        async function startWebcam() {
            try {
                // Request higher resolution to enable digital zoom
                stream = await navigator.mediaDevices.getUserMedia({
                    video: {
                        width: { ideal: 1280 },
                        height: { ideal: 720 },
                        facingMode: 'user'
                    },
                    audio: false
                });
                
                video.srcObject = stream;
                
                // Apply zoom effect using CSS transform
                video.style.transform = 'scale(1.53)'; // Reduced zoom
                video.style.transformOrigin = 'center';
                
                // Start face recognition process once video is ready
                video.onloadedmetadata = function() {
                    // Wait for camera to adjust
                    setTimeout(captureForRecognition, 2000);
                };
                
            } catch (err) {
                console.error('Error accessing the camera: ', err);
                document.getElementById('face-login-message').textContent = 
                    'Unable to access camera. Please check permissions.';
            }
        }
        
        function stopWebcam() {
            if (stream) {
                stream.getTracks().forEach(track => track.stop());
                video.srcObject = null;
            }
        }
        
        function captureForRecognition() {
            // Show processing indicator
            processingIndicator.style.display = 'block';
            
            // Create a temporary canvas with proper aspect ratio
            const tempCanvas = document.createElement('canvas');
            tempCanvas.width = video.videoWidth;
            tempCanvas.height = video.videoHeight;
            const tempCtx = tempCanvas.getContext('2d');
            
            // Draw the original video frame (unstretched) to temp canvas
            tempCtx.drawImage(video, 0, 0, tempCanvas.width, tempCanvas.height);
            
            // Calculate the centered square crop with zoom
            const scale = 1.53; // Match the CSS transform scale
            const size = Math.min(tempCanvas.width, tempCanvas.height) / scale;
            const sourceX = (tempCanvas.width - size) / 2;
            const sourceY = (tempCanvas.height - size) / 2;
            
            // Create the final canvas for face recognition (square)
            const canvas = document.createElement('canvas');
            canvas.width = 260;
            canvas.height = 260;
            const ctx = canvas.getContext('2d');
            
            // Draw the zoomed portion to canvas without distorting
            ctx.drawImage(
                tempCanvas, 
                sourceX, sourceY, size, size,  // Source rectangle (square)
                0, 0, canvas.width, canvas.height  // Destination rectangle (square)
            );
            
            // Convert to blob for sending to server
            canvas.toBlob(function(blob) {
                const formData = new FormData();
                formData.append('face_image', blob);
                
                // Update message
                document.getElementById('face-login-message').textContent = 'Verifying...';
                
                // Send to server for verification
                fetch('/api/face-login', {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-CSRFToken': getCsrfToken()
                    }
                })
                .then(response => {
                    console.log('Response status:', response.status);
                    return response.json();
                })
                .then(data => {
                    console.log('API response:', data);
                    
                    // Hide processing indicator
                    processingIndicator.style.display = 'none';
                    
                    if (data.success) {
                        document.getElementById('face-login-message').textContent = 'Login successful!';
                        
                        // Show success animation
                        const successIcon = document.createElement('div');
                        successIcon.innerHTML = `
                            <svg xmlns="http://www.w3.org/2000/svg" width="60" height="60" viewBox="0 0 24 24" fill="none" stroke="#28a745" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                                <polyline points="22 4 12 14.01 9 11.01"></polyline>
                            </svg>
                        `;
                        successIcon.style.position = 'absolute';
                        successIcon.style.top = '50%';
                        successIcon.style.left = '50%';
                        successIcon.style.transform = 'translate(-50%, -50%)';
                        successIcon.style.animation = 'fadeIn 0.5s ease-in-out';
                        modal.querySelector('.video-container').appendChild(successIcon);
                        
                        // Redirect to dashboard after successful login
                        setTimeout(() => {
                            window.location.href = data.redirect_url;
                        }, 1000);
                    } else {
                        document.getElementById('face-login-message').textContent = 
                            data.message || 'Face not recognized. Please try again.';
                        
                        // Try again after a delay
                        setTimeout(captureForRecognition, 2000);
                    }
                })
                .catch(error => {
                    // Hide processing indicator
                    processingIndicator.style.display = 'none';
                    
                    console.error('Error in face login: ', error);
                    document.getElementById('face-login-message').textContent = 
                        'Error verifying face. Please try again.';
                    
                    // Try again after a delay
                    setTimeout(captureForRecognition, 2000);
                });
            }, 'image/jpeg', 0.9);
        }
        
        // Get CSRF token from meta tag or cookies
        function getCsrfToken() {
            // Try to get CSRF token from meta tag
            const metaToken = document.querySelector('meta[name="csrf-token"]');
            if (metaToken) return metaToken.getAttribute('content');
            
            // Try to get from cookie as fallback
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.startsWith('csrf_token=')) {
                    return cookie.substring('csrf_token='.length, cookie.length);
                }
            }
            
            return '';
        }
        
        // Handle escape key to close modal
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                stopWebcam();
                modal.remove();
                style.remove();
            }
        });
        
        // Start the webcam
        startWebcam();
    });
});