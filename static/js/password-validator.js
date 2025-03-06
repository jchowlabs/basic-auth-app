document.addEventListener('DOMContentLoaded', function() {
    const passwordField = document.querySelector('input[type="password"]');
    if (passwordField) {
        const reqLength = document.getElementById('req-length');
        const reqUppercase = document.getElementById('req-uppercase');
        const reqLowercase = document.getElementById('req-lowercase');
        const reqNumber = document.getElementById('req-number');
        const reqSpecial = document.getElementById('req-special');
        function validatePassword() {
            const password = passwordField.value;
            toggleValid(reqLength, password.length >= 8);
            toggleValid(reqUppercase, /[A-Z]/.test(password));
            toggleValid(reqLowercase, /[a-z]/.test(password));
            toggleValid(reqNumber, /[0-9]/.test(password));
            toggleValid(reqSpecial, /[!@#$%^&*(),.?":{}|<>]/.test(password));
        }
        function toggleValid(element, isValid) {
            if (isValid) {
                element.classList.add('valid');
            } else {
                element.classList.remove('valid');
            }
        }
        passwordField.addEventListener('input', validatePassword);
        validatePassword();
    }
});