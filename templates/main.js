function validatePass(p1, p2) {
2	    if (p1.value != p2.value || p1.value == '' || p2.value == '') {
3	        p2.setCustomValidity('Password incorrect');
4	    } else {
5	        p2.setCustomValidity('');
6	    }
7	}