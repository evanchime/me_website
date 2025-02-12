// Get elements by class name
var elements = document.getElementsByClassName('myAlerts');

// Convert HTMLCollection to an array using ES6 spread syntax
var elementsArray = [...elements];

// Loop through the elements
elementsArray.forEach(function(element) {
  var id = element.getAttribute('id');

  if (id === 'myPasswordNoMatchAlert') {
    element.addEventListener('closed.bs.alert', function(event) {
      // Moving focus to password1
      document.getElementById('password1').focus();
    });
  } else if (id === 'myUsernameExistsAlert') {
    element.addEventListener('closed.bs.alert', function(event) {
      // Moving focus to username
      document.getElementById('username').focus();
    });
  } else if (id === 'myLoginErrorAlert') {
    element.addEventListener('closed.bs.alert', function(event) {
      // Moving focus to username
      document.getElementById('floatingInput').focus();
    });
  } else if (id === 'myEmailExistsAlert') {
    element.addEventListener('closed.bs.alert', function(event) {
      // Moving focus to email
      document.getElementById('email').focus();
    });
  } else if (id === 'myOldPasswordNoMatchAlert') {
    element.addEventListener('closed.bs.alert', function(event) {
      // Moving focus to oldPassword
      document.getElementById('oldPassword').focus();
    });
  }else if (id === "myEmailNoMatchAlert") {
    element.addEventListener('closed.bs.alert', function(event) {
      // Moving focus to email
      document.getElementById('inputEmail').focus();
    });
  }else if (id === "myInputNewPasswordNoMatchAlert") {
    element.addEventListener('closed.bs.alert', function(event) {
      // Moving focus to new password input
      document.getElementById('inputNewPassword').focus();
    });
  }
});

