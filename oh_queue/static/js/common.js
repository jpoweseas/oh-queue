function requestNotificationPermission() {
  try {
    Push.Permission.request(null, function() {
      console.log("Permission denied for notifications");
    })
  } catch (e) {
    // Ignore Push.js errors about unsupported devices
  }
}

function notifyUser(title, body) {
  try {
    Push.create(title, {
      'body': body,
      'icon': window.location.origin + "/static/img/logo-tiny.png",
       onClick: function () {
          window.focus();
          this.close();
      }
    });
  } catch (e) {
    // Ignore Push.js errors about unsupported devices
  }

}

function connectSocket() {
  return io.connect('//' + document.domain + ':' + location.port, {
    transports: ['websocket', 'polling'],
    'sync disconnect on unload' : true
  });
}

// The one and only app. Other components may reference this variable.
// See components/app.js for more documentation
let app = ReactDOM.render(<App/>, document.getElementById('content'));
