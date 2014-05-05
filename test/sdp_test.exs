defmodule SDPTest do
  use ExUnit.Case
  alias Exwebrtc.SDP, as: SDP

  test "password" do
    assert "e103956099236daf77be8198a163137e" == SDP.password(sample_sdp)
  end

  def sample_sdp do
    "v=0\r\no=Mozilla-SIPUA-29.0 24488 0 IN IP4 0.0.0.0\r\ns=SIP Call\r\nt=0 0\r\na=ice-ufrag:2d2c4961\r\na=ice-pwd:e103956099236daf77be8198a163137e\r\na=fingerprint:sha-256 23:D5:3A:C4:2F:4D:89:36:0B:98:56:BC:5F:A0:C3:E8:71:D1:5F:FD:EF:06:FB:63:28:8B:08:00:F2:C4:57:10\r\nm=application 61421 DTLS/SCTP 5000 \r\nc=IN IP4 71.63.48.107\r\na=sctpmap:5000 webrtc-datachannel 16\r\na=setup:active\r\na=candidate:0 1 UDP 2130379007 192.168.42.112 61421 typ host\r\na=candidate:1 1 UDP 1694236671 71.63.48.107 61421 typ srflx raddr 192.168.42.112 rport 61421\r\n"
  end
end