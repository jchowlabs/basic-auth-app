document.addEventListener('DOMContentLoaded', function() {
    const flashMessages = document.querySelectorAll('.alert-dismissing');
    if (flashMessages.length > 0) {
        flashMessages.forEach(function(message) {
            const messageText = message.textContent.trim();
            let displayDuration = determineDuration(messageText);
            console.log(`Message: "${messageText}" - Display duration: ${displayDuration/1000}s`);
            const timer = setTimeout(function() {
                message.classList.add('fade-out');
                setTimeout(function() {
                    message.style.height = message.offsetHeight + 'px';
                    message.style.height = '0';
                    message.style.marginTop = '0';
                    message.style.paddingTop = '0';
                    message.style.paddingBottom = '0';
                    message.style.overflow = 'hidden';
                    setTimeout(function() {
                        message.remove();
                    }, 300);
                }, 500);
            }, displayDuration);
            message.style.cursor = 'pointer';
            message.title = 'Click to dismiss';
            message.addEventListener('click', function() {
                clearTimeout(timer);
                message.classList.add('fade-out');
                setTimeout(function() {
                    message.style.height = message.offsetHeight + 'px';
                    message.style.height = '0';
                    message.style.marginTop = '0';
                    message.style.paddingTop = '0';
                    message.style.paddingBottom = '0';
                    message.style.overflow = 'hidden';
                    setTimeout(function() {
                        message.remove();
                    }, 300);
                }, 500);
            });
        });
    }
    
    /**
     * Determines how long to display a message based on its content
     * @param {string} messageText 
     * @return {number} 
     */
    function determineDuration(messageText) {
        const lowerText = messageText.toLowerCase();
        if (lowerText.includes('too many login attempts') || lowerText.includes('try again in 1 minute')) {
            return 60 * 1000; 
        }
        if (lowerText.includes('account temporarily locked') || lowerText.includes('account locked')) {
            const minutesMatch = lowerText.match(/(\d+)\s*minute/);
            if (minutesMatch && minutesMatch[1]) {
                const minutes = parseInt(minutesMatch[1]);
                if (!isNaN(minutes)) {
                    return minutes * 60 * 1000; 
                }
            }
            return 5 * 60 * 1000; 
        }
        if (lowerText.includes('success') || 
            lowerText.includes('created') || 
            lowerText.includes('registered') ||
            lowerText.includes('welcome')) {
            return 3000; 
        }
        return 5000; 
    }
});