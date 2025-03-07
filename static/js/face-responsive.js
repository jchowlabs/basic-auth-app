function adjustVideoContainer() {
    const container = document.querySelector('.capture-container');
    const videoContainer = document.getElementById('video-container');
    const faceOutline = document.getElementById('face-outline');
    if (videoContainer.style.display !== 'none') {
        videoContainer.style.width = getComputedStyle(faceOutline).width;
        videoContainer.style.height = getComputedStyle(faceOutline).height;
    }
    if (window.innerWidth < 340) {
        container.style.maxWidth = (window.innerWidth - 60) + 'px';
    }
    if (window.innerHeight < 500 && window.innerWidth > window.innerHeight) {
        const maxHeight = window.innerHeight - 80; 
        if (maxHeight < 300) {
            container.style.maxHeight = maxHeight + 'px';
            container.style.width = (maxHeight * 0.86) + 'px';
        }
    }
}
document.addEventListener('DOMContentLoaded', function() {
    adjustVideoContainer();
    window.addEventListener('resize', adjustVideoContainer);
    const captureBtn = document.getElementById('capture-btn');
    if (captureBtn) {
        captureBtn.addEventListener('click', function() {
            const videoContainer = document.getElementById('video-container');
            const faceOutline = document.getElementById('face-outline');
            videoContainer.style.width = getComputedStyle(faceOutline).width;
            videoContainer.style.height = getComputedStyle(faceOutline).height;
            setTimeout(adjustVideoContainer, 50);
        });
    }
});