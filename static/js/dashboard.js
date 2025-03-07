document.addEventListener('DOMContentLoaded', function() {
    setupFlashMessages();
    const deletePasskeyBtn = document.getElementById('delete-passkey-btn');
    if (deletePasskeyBtn) {
        deletePasskeyBtn.addEventListener('click', function() {
            if (confirm('Are you sure you want to delete your Passkey?')) {
                // Clear any existing flash messages first
                clearFlashMessages();
                
                fetch('/api/delete-passkey', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCsrfToken()
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        location.reload();
                    } else {
                        alert('Failed to delete Passkey. Please try again.');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error occurred. Please try again later.');
                });
            }
        });
    }
    const deleteFaceBtn = document.getElementById('delete-face-btn');
    if (deleteFaceBtn) {
        deleteFaceBtn.addEventListener('click', function() {
            if (confirm('Are you sure you want to delete your Face ID?')) {
                // Clear any existing flash messages first
                clearFlashMessages();
                
                fetch('/api/delete-face', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCsrfToken()
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        location.reload();
                    } else {
                        alert('Failed to delete Face ID. Please try again.');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error occurred. Please try again later.');
                });
            }
        });
    }
    const addVoiceBtn = document.getElementById('add-voice-btn');
    if (addVoiceBtn) {
        addVoiceBtn.addEventListener('click', function() {
            // Clear any existing flash messages first
            clearFlashMessages();
            
            // Show modal dialog or redirect to voice registration page
            alert('Voice ID registration coming soon');
            
            // Uncomment when implementing actual voice registration
            /*
            fetch('/api/register-voice', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCsrfToken()
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.href = '/voice-registration';
                } else {
                    alert('Failed to initialize voice registration. Please try again.');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('An error occurred. Please try again later.');
            });
            */
        });
    }
    
    // Handle voice ID deletion (placeholder)
    const deleteVoiceBtn = document.getElementById('delete-voice-btn');
    if (deleteVoiceBtn) {
        deleteVoiceBtn.addEventListener('click', function() {
            if (confirm('Are you sure you want to delete your Voice ID?')) {
                // Clear any existing flash messages first
                clearFlashMessages();
                
                // Placeholder for actual deletion logic
                alert('Voice ID deletion feature coming soon!');
                
                // Uncomment when implementing actual voice deletion
                /*
                fetch('/api/delete-voice', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCsrfToken()
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        location.reload();
                    } else {
                        alert('Failed to delete Voice ID. Please try again.');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error occurred. Please try again later.');
                });
                */
            }
        });
    }
    
    // Helper function to get CSRF token
    function getCsrfToken() {
        const metaTag = document.querySelector('meta[name="csrf-token"]');
        return metaTag ? metaTag.getAttribute('content') : '';
    }
    
    // Helper function to clear existing flash messages
    function clearFlashMessages() {
        const alertContainer = document.getElementById('alert-container');
        if (alertContainer) {
            alertContainer.innerHTML = '';
        }
    }
    
    // Function to set up flash message handling
    function setupFlashMessages() {
        const flashMessages = document.querySelectorAll('.alert-dismissing');
        
        // Only show the most recent flash message if there are multiple
        if (flashMessages.length > 1) {
            // Keep only the last message
            for (let i = 0; i < flashMessages.length - 1; i++) {
                flashMessages[i].remove();
            }
        }
        
        // Handle the remaining message(s)
        if (flashMessages.length > 0) {
            flashMessages.forEach(function(message) {
                // Start fade out after 3 seconds
                setTimeout(function() {
                    message.classList.add('fade-out');
                    
                    // Remove element after animation completes
                    setTimeout(function() {
                        message.remove();
                    }, 1000); // Longer duration to match the enhanced transition
                }, 3000);
            });
        }
    }
});