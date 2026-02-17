'use strict';

var carelink = {
  name: 'carelink'
  , label: 'CareLink Authentication'
  , pluginType: 'admin'
};

function init () {
  return carelink;
}

module.exports = init;

var $status = null;

carelink.actions = [{
  name: 'CareLink OAuth Login'
  , description: 'Authenticate with Medtronic CareLink to generate OAuth tokens. After clicking "Start Login", a new tab will open. Log in with your CareLink credentials, then copy the URL from the address bar when the page fails to load, and paste it below.'
  , buttonLabel: 'Start Login'
  , preventClose: true
  , init: function init (client) {
    $status = $('#admin_' + carelink.name + '_0_status');
    var $html = $('#admin_' + carelink.name + '_0_html');

    // Build the UI
    var ui =
      '<div id="carelink_auth_ui" style="margin-top:10px">' +
      '  <div id="carelink_status_row" style="margin-bottom:10px"></div>' +
      '  <div style="margin-bottom:8px">' +
      '    <label for="carelink_region">' + client.translate('Region') + ': </label>' +
      '    <select id="carelink_region" style="padding:4px">' +
      '      <option value="eu">EU (Europe)</option>' +
      '      <option value="us">US (United States)</option>' +
      '    </select>' +
      '  </div>' +
      '  <div id="carelink_paste_section" style="display:none; margin-top:10px; padding:10px; border:1px solid #555; border-radius:4px">' +
      '    <p style="margin:0 0 8px 0"><strong>' + client.translate('Step 2') + ':</strong> ' +
           client.translate('After logging in (and CAPTCHA if prompted), the page will fail to load. Open DevTools (F12) > Network tab, find the blocked GET request to /authorize/resume, click it > Headers > Response Headers > copy the "Location" value (starts with "com.medtronic.carepartner:/sso?code=...") and paste it below.') + '</p>' +
      '    <input id="carelink_callback_url" type="text" style="width:100%; padding:6px; box-sizing:border-box" placeholder="com.medtronic.carepartner:/sso?code=..." />' +
      '    <br><br>' +
      '    <button id="carelink_exchange_btn" class="adminButton" style="display:inline-block">' + client.translate('Complete Login') + '</button>' +
      '    <span id="carelink_exchange_status" style="margin-left:10px"></span>' +
      '  </div>' +
      '</div>';

    $html.append($(ui));

    // Load current status
    checkStatus(client);

    // Wire up the exchange button
    $('#carelink_exchange_btn').click(function (event) {
      event.preventDefault();
      completeLogin(client);
    });
  }
  , code: function startLogin (client) {
    startAuth(client);
  }
}];

// State for the current auth flow
var pendingState = null;

function checkStatus (client) {
  $.ajax({
    method: 'GET'
    , url: '/api/v2/carelink/status'
    , headers: client.headers()
  }).done(function (data) {
    var $row = $('#carelink_status_row');
    if (data.configured) {
      var statusText = 'CareLink: Connected';
      if (data.region) statusText += ' (' + data.region.toUpperCase() + ')';
      if (data.expiresInMinutes !== null) {
        statusText += ' — token expires in ' + data.expiresInMinutes + ' min';
      }
      if (data.tokenExpired) {
        statusText += ' (expired, will refresh)';
      }
      $row.html('<span style="color:#4CAF50">' + statusText + '</span>');
    } else {
      $row.html('<span style="color:#FF9800">CareLink: ' + (data.message || 'Not configured') + '</span>');
    }
  }).fail(function () {
    $('#carelink_status_row').html('<span style="color:#999">Could not check status</span>');
  });
}

function startAuth (client) {
  var region = $('#carelink_region').val();
  $status.hide().text(client.translate('Contacting CareLink...')).fadeIn('slow');

  $.ajax({
    method: 'POST'
    , url: '/api/v2/carelink/auth-url'
    , headers: client.headers()
    , contentType: 'application/json'
    , data: JSON.stringify({ region: region })
  }).done(function (data) {
    pendingState = data.state;

    // Open authorize URL in new tab
    window.open(data.authorizeUrl, '_blank');

    // Show paste section
    $('#carelink_paste_section').fadeIn('slow');
    $('#carelink_callback_url').val('').focus();
    $status.hide().text(client.translate('Login page opened in new tab. Complete login, then paste the URL below.')).fadeIn('slow');
  }).fail(function (err) {
    var msg = err.responseJSON ? err.responseJSON.message : 'Failed to start auth flow';
    $status.hide().text(client.translate('Error') + ': ' + msg).fadeIn('slow');
  });
}

function completeLogin (client) {
  var callbackUrl = $('#carelink_callback_url').val();
  if (!callbackUrl) {
    $('#carelink_exchange_status').text(client.translate('Please paste the URL first'));
    return;
  }
  if (!pendingState) {
    $('#carelink_exchange_status').text(client.translate('No active login session. Click "Start Login" first.'));
    return;
  }

  $('#carelink_exchange_status').text(client.translate('Exchanging tokens...'));

  $.ajax({
    method: 'POST'
    , url: '/api/v2/carelink/exchange'
    , headers: client.headers()
    , contentType: 'application/json'
    , data: JSON.stringify({ state: pendingState, callbackUrl: callbackUrl })
  }).done(function (data) {
    pendingState = null;
    $('#carelink_paste_section').fadeOut('slow');
    $('#carelink_exchange_status').text('');
    $status.hide().text(client.translate('Login successful!') + (data.country ? ' Country: ' + data.country : '') + (data.expiresInMinutes ? ' Token expires in ' + data.expiresInMinutes + ' min.' : '')).fadeIn('slow');

    // Refresh status display
    checkStatus(client);
  }).fail(function (err) {
    var msg = err.responseJSON ? err.responseJSON.message : 'Token exchange failed';
    $('#carelink_exchange_status').text(client.translate('Error') + ': ' + msg);
  });
}
