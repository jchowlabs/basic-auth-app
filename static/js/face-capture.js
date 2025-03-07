document.addEventListener('DOMContentLoaded', function() {
    const video = document.getElementById('video');
    const canvas = document.getElementById('canvas');
    const captureBtn = document.getElementById('capture-btn');
    const faceOutline = document.getElementById('face-outline');
    const videoContainer = document.getElementById('video-container');
    const countdownElement = document.getElementById('countdown');
    let stream = null;
    canvas.width = 260;
    canvas.height = 260;
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
            faceOutline.style.display = 'none';
            videoContainer.style.display = 'block';
            video.onloadedmetadata = function() {
                setTimeout(() => {
                    startCountdown();
                }, 1500);
            };
        } catch (err) {
            console.error('Error accessing the camera: ', err);
            alert('Please allow camera access for FaceID.');
        }
    }
    function stopWebcam() {
        if (stream) {
            stream.getTracks().forEach(track => track.stop());
            video.srcObject = null;
        }
    }
    function captureImage() {
        const tempCanvas = document.createElement('canvas');
        tempCanvas.width = video.videoWidth;
        tempCanvas.height = video.videoHeight;
        const tempCtx = tempCanvas.getContext('2d');
        tempCtx.drawImage(video, 0, 0, tempCanvas.width, tempCanvas.height);
        const scale = 1.25;
        const size = Math.min(tempCanvas.width, tempCanvas.height) / scale;
        const sourceX = (tempCanvas.width - size) / 2;
        const sourceY = (tempCanvas.height - size) / 2;
        const ctx = canvas.getContext('2d');
        canvas.width = 260; 
        canvas.height = 260;
        ctx.drawImage(
            tempCanvas, 
            sourceX, sourceY, size, size,
            0, 0, canvas.width, canvas.height  
        );
        canvas.toBlob(function(blob) {
            const formData = new FormData();
            formData.append('face_image', blob, 'face.jpg');
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
                    window.location.href = data.redirect_url || '/dashboard?face_registered=true';
                } else {
                    console.error('Face registration failed:', data.message);
                    alert(data.message || 'Please ensure your face is in the circle.');
                    videoContainer.style.display = 'none';
                    faceOutline.style.display = 'flex';
                    captureBtn.disabled = false;
                }
            })
            .catch(error => {
                console.error('Error uploading face image: ', error);
                alert('Registration failed. Please try again.');
                videoContainer.style.display = 'none';
                faceOutline.style.display = 'flex';
                captureBtn.disabled = false;
            });
        }, 'image/jpeg', 0.9);
    }
    function startCountdown() {
        countdownElement.style.display = 'block';
        let count = 3;  
        countdownElement.textContent = count;
        const countdown = setInterval(() => {
            count--;
            countdownElement.textContent = count;
            
            if (count === 0) {
                clearInterval(countdown);
                setTimeout(() => {
                    countdownElement.style.display = 'none';
                    captureImage();
                    stopWebcam();
                }, 1000);
            }
        }, 1000);
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
    captureBtn.addEventListener('click', function() {
        this.disabled = true;
        startWebcam();
    });
});