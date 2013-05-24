function validatePass(p1, p2) {
    if (p1.value != p2.value || p1.value.length < 4 || p2.value.length < 4) {
        p2.setCustomValidity('Password incorrect!');
    } else {
        p2.setCustomValidity('');
    }
}

function validateLength(p1) {
    if (p1.value.length < 4) {
        p1.setCustomValidity('Legth too small!');
    } else {
        p1.setCustomValidity('');
    }
}