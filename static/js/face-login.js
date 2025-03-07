document.addEventListener('DOMContentLoaded', function() {
    console.log("Face login script loaded");
    const loginFaceBtn = document.getElementById('login-face-btn');
    if (!loginFaceBtn) {
        console.error("Login face button not found");
        return;
    }
    loginFaceBtn.addEventListener('click', function() {
        console.log("Login with Face ID button clicked");
        const modal = document.createElement('div');
        modal.className = 'face-login-modal';
        modal.innerHTML = `
            <div class="face-login-content">
                <div class="face-login-body">
                    <div class="video-container">
                        <video id="face-login-video" playsinline autoplay></video>
                        <div class="processing-indicator"></div>
                    </div>
                    <div id="face-login-message">Starting verification...</div>
                    <div class="login-options">
                        <a href="/" class="alternative-login">Cancel</a>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
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
                transition: opacity 0.3s ease-out;
                padding: 15px;
                box-sizing: border-box;
            }
            
            .face-login-modal.fade-out {
                opacity: 0;
            }
            
            .face-login-content {
                background-color: white;
                border-radius: 8px;
                width: 100%;
                max-width: 500px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.2);
                animation: slideIn 0.3s ease-out;
                padding-top: 20px;
                transition: transform 0.3s ease-out, opacity 0.3s ease-out;
                position: relative;
                margin: 0 auto;
            }
            
            .fade-out .face-login-content {
                transform: translateY(-20px);
                opacity: 0;
            }
            
            .face-login-body {
                padding: 20px;
                text-align: center;
                display: flex;
                flex-direction: column;
                align-items: center;
            }
            
            .video-container {
                width: 100%;
                max-width: 345px;
                height: auto;
                aspect-ratio: 0.86 / 1; /* Maintains the height ratio regardless of width */
                border-radius: 50% / 40%;
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
                width: 100%;
            }
            
            .login-options {
                margin-top: 20px;
                padding-top: 15px;
                border-top: 1px solid #eee;
                width: 100%;
            }
            
            .alternative-login {
                color: #007bff;
                text-decoration: none;
                font-size: 0.9rem;
                transition: color 0.2s;
                display: inline-block;
                padding: 8px 0;
            }
            
            .alternative-login:hover {
                color: #0056b3;
                text-decoration: underline;
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
            
            .timer-bar {
                height: 4px;
                background-color: #007bff;
                position: absolute;
                bottom: 0;
                left: 0;
                width: 100%;
                transform-origin: left;
                animation: timerShrink 16s linear forwards;
            }
            
            @keyframes timerShrink {
                from { transform: scaleX(1); }
                to { transform: scaleX(0); }
            }
            
            @keyframes spin {
                to { transform: translate(-50%, -50%) rotate(360deg); }
            }
            
            /* Responsive Breakpoints */
            @media (max-width: 600px) {
                .face-login-content {
                    max-width: 95%;
                }
                
                .video-container {
                    max-width: 280px;
                    border-width: 2px;
                }
                
                #face-login-message {
                    font-size: 0.85rem;
                }
            }
            
            @media (max-width: 400px) {
                .face-login-body {
                    padding: 15px 10px;
                }
                
                .video-container {
                    max-width: 230px;
                }
                
                .processing-indicator {
                    width: 50px;
                    height: 50px;
                    border-width: 4px;
                }
            }
            
            @media (max-height: 700px) {
                .video-container {
                    max-height: 60vh;
                }
                
                .face-login-body {
                    padding-top: 10px;
                    padding-bottom: 10px;
                }
            }
            
            /* Orientation-specific adjustments */
            @media (orientation: landscape) and (max-height: 500px) {
                .face-login-content {
                    display: flex;
                    flex-direction: row;
                    align-items: center;
                    max-width: 90%;
                }
                
                .face-login-body {
                    display: flex;
                    flex-direction: row;
                    flex-wrap: wrap;
                    justify-content: center;
                    padding: 10px;
                }
                
                .video-container {
                    max-width: 200px;
                    max-height: 70vh;
                    margin-right: 15px;
                    flex: 0 0 auto;
                }
                
                #face-login-message {
                    flex: 1 1 auto;
                    text-align: left;
                    margin-top: 0;
                    padding-left: 10px;
                }
                
                .login-options {
                    width: 100%;
                    margin-top: 10px;
                }
            }
        `;
        document.head.appendChild(style);
        const processingIndicator = modal.querySelector('.processing-indicator');
        const timerBar = document.createElement('div');
        timerBar.className = 'timer-bar';
        modal.querySelector('.face-login-content').appendChild(timerBar);
        function adjustVideoContainer() {
            const videoContainer = modal.querySelector('.video-container');
            const modalContent = modal.querySelector('.face-login-content');
            if (window.innerWidth < 340) {
                videoContainer.style.maxWidth = (window.innerWidth - 60) + 'px';
            }
            if (window.innerHeight < 500 && window.innerWidth > window.innerHeight) {
                if (videoContainer && modalContent) {
                    const maxHeight = window.innerHeight - 80;
                    if (maxHeight < 300) {
                        videoContainer.style.maxHeight = maxHeight + 'px';
                        videoContainer.style.width = (maxHeight * 0.86) + 'px';
                    }
                }
            }
        }
        adjustVideoContainer();
        window.addEventListener('resize', adjustVideoContainer);
        function cleanupListeners() {
            window.removeEventListener('resize', adjustVideoContainer);
        }
        const video = document.getElementById('face-login-video');
        let stream = null;
        let faceDetected = false;
        const totalTimeout = 16000;       // 16 seconds total
        const startingPhase = 2000;       // First 2 seconds: "Starting verification..."
        const verifyingPhase = 4000;      // Next 4 seconds: "Verification in-progress..."
        const ensureFacePhase = 3500;     // Next 3.5 seconds: "Ensure your face fills the circle."
        const notRecognizedPhase = 3500;  // Next 3.5 seconds: "Hmm, face not recognized..."
        const tryAgainPhase = 3000;       // Final 3 seconds: "Sorry, face not recognized. Try Again."
        
        // Initialize timers
        let startingPhaseTimer = null;
        let verifyingPhaseTimer = null;
        let ensureFacePhaseTimer = null;
        let notRecognizedPhaseTimer = null;
        let finalPhaseTimer = null;
        
        async function startWebcam() {
            try {
                stream = await navigator.mediaDevices.getUserMedia({
                    video: {
                        width: { ideal: 1280 },
                        height: { ideal: 720 },
                        facingMode: 'user'
                    },
                    audio: false
                });
                
                video.srcObject = stream;
                video.style.transform = 'scale(1.25)';
                video.style.transformOrigin = 'center';
                video.onloadedmetadata = function() {
                    startingPhaseTimer = setTimeout(() => {
                        if (!faceDetected) {
                            document.getElementById('face-login-message').textContent = 'Verification in-progress...';
                            setTimeout(captureForRecognition, 500);
                        }
                    }, startingPhase);
                    verifyingPhaseTimer = setTimeout(() => {
                        if (!faceDetected) {
                            document.getElementById('face-login-message').textContent = 
                                'Ensure your face fills the circle.';
                        }
                    }, startingPhase + verifyingPhase);
                    ensureFacePhaseTimer = setTimeout(() => {
                        if (!faceDetected) {
                            document.getElementById('face-login-message').textContent = 
                                'Hmm, face not recognized...';
                        }
                    }, startingPhase + verifyingPhase + ensureFacePhase);
                    notRecognizedPhaseTimer = setTimeout(() => {
                        if (!faceDetected) {
                            document.getElementById('face-login-message').textContent = 
                                'Sorry, face not recognized. Try again.';
                        }
                    }, startingPhase + verifyingPhase + ensureFacePhase + notRecognizedPhase);
                    finalPhaseTimer = setTimeout(() => {
                        if (!faceDetected) {
                            cleanupAndRedirect();
                        }
                    }, totalTimeout);
                };
            } catch (err) {
                console.error('Error accessing the camera: ', err);
                document.getElementById('face-login-message').textContent = 
                    'Please allow camera access for FaceID.';
            }
        }
        function stopWebcam() {
            if (stream) {
                stream.getTracks().forEach(track => track.stop());
                video.srcObject = null;
            }
        }
        function cleanupAndRedirect() {
            modal.classList.add('fade-out');
            setTimeout(() => {
                stopWebcam();
                if (startingPhaseTimer) clearTimeout(startingPhaseTimer);
                if (verifyingPhaseTimer) clearTimeout(verifyingPhaseTimer);
                if (ensureFacePhaseTimer) clearTimeout(ensureFacePhaseTimer);
                if (notRecognizedPhaseTimer) clearTimeout(notRecognizedPhaseTimer);
                if (finalPhaseTimer) clearTimeout(finalPhaseTimer);
                cleanupListeners();
                modal.remove();
                style.remove();
                window.location.href = '/';
            }, 300);
        }
        function captureForRecognition() {
            if (faceDetected) return;
            processingIndicator.style.display = 'block';
            const tempCanvas = document.createElement('canvas');
            tempCanvas.width = video.videoWidth;
            tempCanvas.height = video.videoHeight;
            const tempCtx = tempCanvas.getContext('2d');
            tempCtx.drawImage(video, 0, 0, tempCanvas.width, tempCanvas.height);
            const scale = 1.25;
            const size = Math.min(tempCanvas.width, tempCanvas.height) / scale;
            const sourceX = (tempCanvas.width - size) / 2;
            const sourceY = (tempCanvas.height - size) / 2;
            const canvas = document.createElement('canvas');
            canvas.width = 260;
            canvas.height = 260;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(
                tempCanvas, 
                sourceX, sourceY, size, size,  
                0, 0, canvas.width, canvas.height 
            );
            canvas.toBlob(function(blob) {
                const formData = new FormData();
                formData.append('face_image', blob);
                fetch('/api/face-login', {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-CSRFToken': getCsrfToken()
                    }
                })
                .then(response => response.json())
                .then(data => {
                    processingIndicator.style.display = 'none';
                    if (data.success) {
                        faceDetected = true;
                        if (startingPhaseTimer) clearTimeout(startingPhaseTimer);
                        if (verifyingPhaseTimer) clearTimeout(verifyingPhaseTimer);
                        if (ensureFacePhaseTimer) clearTimeout(ensureFacePhaseTimer);
                        if (notRecognizedPhaseTimer) clearTimeout(notRecognizedPhaseTimer);
                        if (finalPhaseTimer) clearTimeout(finalPhaseTimer); 
                        document.getElementById('face-login-message').textContent = 'Login successful!';
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
                        timerBar.style.animationPlayState = 'paused';
                        timerBar.style.backgroundColor = '#28a745';
                        setTimeout(() => {
                            modal.classList.add('fade-out');
                            setTimeout(() => {
                                window.location.href = data.redirect_url;
                            }, 300);
                        }, 1000);
                    } else {
                        const elapsedTime = Date.now() - startTime;
                        if (elapsedTime < totalTimeout - 2000) { 
                            setTimeout(captureForRecognition, 1000);
                        }
                    }
                })
                .catch(error => {
                    processingIndicator.style.display = 'none';
                    console.error('Error in face login: ', error);
                    const elapsedTime = Date.now() - startTime;
                    if (elapsedTime < totalTimeout - 2000) { 
                        setTimeout(captureForRecognition, 1000);
                    }
                });
            }, 'image/jpeg', 0.9);
        }
        function getCsrfToken() {
            const metaToken = document.querySelector('meta[name="csrf-token"]');
            if (metaToken) return metaToken.getAttribute('content');
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.startsWith('csrf_token=')) {
                    return cookie.substring('csrf_token='.length, cookie.length);
                }
            }
            
            return '';
        }
        const alternativeLoginLink = modal.querySelector('.alternative-login');
        alternativeLoginLink.addEventListener('click', function(event) {
            event.preventDefault();
            modal.classList.add('fade-out');
            setTimeout(() => {
                // Clear timers
                if (startingPhaseTimer) clearTimeout(startingPhaseTimer);
                if (verifyingPhaseTimer) clearTimeout(verifyingPhaseTimer);
                if (ensureFacePhaseTimer) clearTimeout(ensureFacePhaseTimer);
                if (notRecognizedPhaseTimer) clearTimeout(notRecognizedPhaseTimer);
                if (finalPhaseTimer) clearTimeout(finalPhaseTimer);
                cleanupListeners();
                stopWebcam();
                window.location.href = alternativeLoginLink.getAttribute('href');
            }, 300);
        });
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                cleanupAndRedirect();
            }
        });
        const startTime = Date.now();
        startWebcam();
    });
});