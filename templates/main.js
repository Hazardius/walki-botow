function validatePass(p1, p2) {
    if (p1.value != p2.value || p1.value.length < 4 || p2.value.length < 4) {
        p2.setCustomValidity('Password incorrect!');
    } else {
        p2.setCustomValidity('');
    }
}

function validateUsername(p1) {
    if (p1.value.length < 4) {
        p1.setCustomValidity('Legth too small!');
    } else if (/[a-zA-Z]/.test(p1.value) == false) {
        p1.setCustomValidity('Strange letters used!');
    } else {
        p1.setCustomValidity('');
    }
}