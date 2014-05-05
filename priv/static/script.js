var PeerConnection = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
var SessionDescription = window.RTCSessionDescription || window.mozRTCSessionDescription || window.webkitRTCSessionDescription;

var serverChannel;

var startButton = document.getElementById('startButton');
var sendButton = document.getElementById('sendButton');
var closeButton = document.getElementById('closeButton');
startButton.disabled = false;
sendButton.disabled = true;
closeButton.disabled = true;
startButton.onclick = createConnection;
sendButton.onclick = sendData;
closeButton.onclick = closeDataChannels;

function trace(text) {
  console.log.apply(console, arguments);
  //console.log((performance.now() / 1000).toFixed(3) + ": " + text);
}

var serverSDP = [
  "v=0",
  "o=Mozilla-SIPUA-28.0 17836 0 IN IP4 71.63.48.107",
  "s=SIP Call",
  "t=0 0",
  "a=ice-ufrag:3081b21e",
  "a=ice-pwd:9b4424d9e8c5e253c0290d63328b55b3",
  "a=fingerprint:sha-256 53:CE:F0:CC:D5:09:EE:CD:A4:AE:31:22:09:EE:27:FE:2B:7D:E7:D4:F1:F6:3B:A5:1F:DB:69:30:19:49:57:1B",
  "m=application 4489 DTLS/SCTP 5000",
  "c=IN IP4 192.168.42.112",
  "a=sctpmap:5000 webrtc-datachannel 16",
  "a=setup:actpass",
  "a=candidate:0 1 UDP 2130379007 192.168.42.112 4488 typ host",
  "a=candidate:0 2 UDP 2130379006 192.168.42.112 4489 typ host"
].join('\r\n');
var serverOffer = {"type": "offer", "sdp": serverSDP};

function createConnection() {
  var servers = null;
  window.serverConnection = new PeerConnection(servers, {optional: [{RtpDataChannels: true}]});
  trace('Created local peer connection object serverConnection');

  try {
    // Reliable Data Channels not yet supported in Chrome
    serverChannel = serverConnection.createDataChannel("sendDataChannel", {reliable: false});
    trace('Created send data channel');
  } catch (e) {
    alert('Failed to create data channel. ' +
          'You need Chrome M25 or later with RtpDataChannel enabled');
    trace('createDataChannel() failed with exception: ' + e.message);
  }
  serverConnection.onicecandidate = gotServerCandidate;
  serverConnection.onsignalingstatechange = console.log;
  serverChannel.onmessage = handleMessage;
  serverChannel.onopen = handleServerChannelStateChange;
  serverChannel.onclose = handleServerChannelStateChange;

  serverConnection.setRemoteDescription(new SessionDescription(serverOffer), function() {
    serverConnection.createAnswer(createAnswerCallback, createAnswerErrback);
  }, function() {
    console.error("Error setting remote description", arguments);
  });

  startButton.disabled = true;
  closeButton.disabled = false;
}

function createAnswerCallback(desc) {
  $.ajax('/answer_sdp', {
    data : JSON.stringify(desc),
    contentType : 'application/json',
    type : 'POST'
  });
  console.log('createAnswerCallback result', desc.sdp);
  serverConnection.setLocalDescription(desc);
}

function createAnswerErrback() {
  console.error('createAnswerErrback', arguments);
}

function gotServerCandidate(event) {
  console.log('local ice callback', event);
  if (event.candidate) {
    trace('Local ICE candidate: \n' + event.candidate.candidate);
  }
}

function sendData() {
  var data = document.getElementById("dataChannelSend").value;
  serverChannel.send(data);
  trace('Sent data: ' + data);
}

function closeDataChannels() {
  trace('Closing data channels');
  serverChannel.close();
  trace('Closed data channel with label: ' + serverChannel.label);
  //trace('Closed data channel with label: ' + receiveChannel.label);
  serverConnection.close();
  serverConnection = null;
  trace('Closed peer connections');
  startButton.disabled = false;
  sendButton.disabled = true;
  closeButton.disabled = true;
  dataChannelSend.value = "";
  dataChannelReceive.value = "";
  dataChannelSend.disabled = true;
  dataChannelSend.placeholder = "Press Start, enter some text, then press Send.";
}

function handleMessage(event) {
  trace('Received message: ' + event.data);
  document.getElementById("dataChannelReceive").value = event.data;
}

function handleServerChannelStateChange() {
  var readyState = serverChannel.readyState;
  trace('Send channel state is: ' + readyState);
  if (readyState == "open") {
    dataChannelSend.disabled = false;
    dataChannelSend.focus();
    dataChannelSend.placeholder = "";
    sendButton.disabled = false;
    closeButton.disabled = false;
  } else {
    dataChannelSend.disabled = true;
    sendButton.disabled = true;
    closeButton.disabled = true;
  }
}
