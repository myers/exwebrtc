# Exwebrtc - WebRTC for Elixir - a work in progress

WebRTC allows browser to directly connect to each other and stream audio/video and data.  One cool trick this allows is sending datagram packets between browsers, which are useful for fast pace games where a little bit of packet loss would ruin your day if you where using TCP (like WebSockets).  My goal here is to create library that allows me to write a game server that uses WebRTC Data Channels between the server and web browser based client.

The downside of WebRTC is it's a amalgamation of protocols that aren't yet well supported.  To communicate with a WebRTC data channel a server needs to:
 * Multiplex all communication over one UDP socket
 * Listen for a STUN request and respond
 * Send it's own STUN request and read the response
 * Accept a DTLS client connection and extract the SCTP packet
 * Parse the SCTP and feed your application the data

# Current status

The demo can use STUN to negotiate what ports to use.  With Firefox (and some tweaking of the SDP to put in the right IP addresses) I can get the browser to start the DTLS handshake.  Now working on reading those DTLS packets.

# Future plans

I'm hoping to help support development of Erlang's DTLS library.  It's partially complete in Erlang 17.  I'm hoping that the current SCTP library in Erlang will be able to parse the packets created by Browsers, but perhaps there is a disagreement on the standards.