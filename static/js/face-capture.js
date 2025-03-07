document.addEventListener('DOMContentLoaded', function() {
    const video = document.getElementById('video');
    const canvas = document.getElementById('canvas');
    const captureBtn = document.getElementById('capture-btn');
    const faceOutline = document.getElementById('face-outline');
    const videoContainer = document.getElementById('video-container');
    const countdownElement = document.getElementById('countdown');
    
    let stream = null;
    
    // Set canvas size
    canvas.width = 260;
    canvas.height = 260;
    
    // Function to start webcam with zoom
    async function startWebcam() {
        try {
            // Request high resolution to enable digital zoom
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
            
            // Show video container, hide outline
            faceOutline.style.display = 'none';
            videoContainer.style.display = 'block';
            
            // Start countdown after camera is ready
            video.onloadedmetadata = function() {
                // Give camera time to adjust focus and exposure
                setTimeout(() => {
                    startCountdown();
                }, 1500);
            };
        } catch (err) {
            console.error('Error accessing the camera: ', err);
            alert('Unable to access the camera. Please make sure you have granted camera permissions.');
        }
    }
    
    // Function to stop webcam
    function stopWebcam() {
        if (stream) {
            stream.getTracks().forEach(track => track.stop());
            video.srcObject = null;
        }
    }
    
    // Function to capture image without stretching
    function captureImage() {
        // Create a temporary canvas with proper aspect ratio
        const tempCanvas = document.createElement('canvas');
        tempCanvas.width = video.videoWidth;
        tempCanvas.height = video.videoHeight;
        const tempCtx = tempCanvas.getContext('2d');
        
        // Draw the original video frame (unstretched) to temp canvas
        tempCtx.drawImage(video, 0, 0, tempCanvas.width, tempCanvas.height);
        
        // Calculate the centered square crop with zoom
        const scale = 1.53; // Zoom level
        const size = Math.min(tempCanvas.width, tempCanvas.height) / scale;
        const sourceX = (tempCanvas.width - size) / 2;
        const sourceY = (tempCanvas.height - size) / 2;
        
        // Now draw to the actual canvas without distorting aspect ratio
        const ctx = canvas.getContext('2d');
        canvas.width = 260;  // Use a square canvas for face recognition
        canvas.height = 260;
        
        ctx.drawImage(
            tempCanvas, 
            sourceX, sourceY, size, size,  // Source rectangle (square)
            0, 0, canvas.width, canvas.height  // Destination rectangle (square)
        );
        
        // Convert canvas to blob for file upload
        canvas.toBlob(function(blob) {
            const formData = new FormData();
            formData.append('face_image', blob, 'face.jpg');
            
            // Send image to server
            fetch('/api/save-face', {
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
                if (data.success) {
                    // Let the server handle the success message via flash
                    window.location.href = data.redirect_url || '/dashboard?face_registered=true';
                } else {
                    console.error('Face registration failed:', data.message);
                    alert('Failed to register face: ' + (data.message || 'Unknown error'));
                    // Reset to allow another attempt
                    videoContainer.style.display = 'none';
                    faceOutline.style.display = 'flex';
                    captureBtn.disabled = false;
                }
            })
            .catch(error => {
                console.error('Error uploading face image: ', error);
                alert('Failed to upload image. Please try again.');
                // Reset to allow another attempt
                videoContainer.style.display = 'none';
                faceOutline.style.display = 'flex';
                captureBtn.disabled = false;
            });
        }, 'image/jpeg', 0.9);
    }
    
    // Function for countdown
    function startCountdown() {
        countdownElement.style.display = 'block';
        let count = 3;  
        countdownElement.textContent = count;
        
        const countdown = setInterval(() => {
            count--;
            countdownElement.textContent = count;
            
            if (count === 0) {
                clearInterval(countdown);
                // Hide countdown after it reaches 0
                setTimeout(() => {
                    countdownElement.style.display = 'none';
                    captureImage();
                    stopWebcam();
                }, 1000);
            }
        }, 1000);
    }
    
    // Get CSRF token from meta tag or cookies
    function getCsrfToken() {
        const metaToken = document.querySelector('meta[name="csrf-token"]');
        if (metaToken) return metaToken.getAttribute('content');
        
        // Try to extract from cookies as fallback
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.startsWith('csrf_token=')) {
                return cookie.substring('csrf_token='.length, cookie.length);
            }
        }
        return '';
    }
    
    // Event listener for capture button
    captureBtn.addEventListener('click', function() {
        this.disabled = true; // Prevent multiple clicks
        startWebcam();
    });
});