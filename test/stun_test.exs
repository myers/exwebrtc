defmodule STUNTest do
  use ExUnit.Case
  alias Exwebrtc.STUN, as: STUN

  test "string_xor" do
    assert <<235, 250>> == STUN.string_xor(<<51944 :: size(16)>>, <<33, 18, 164, 66>>)
  end

  test "ip_address_to_binary" do
    assert <<192, 168, 42, 8>> == STUN.ip_address_to_binary("192.168.42.8")
  end

  test "encode_xor_mapped_address" do
    # from the captured request
    target = <<0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xeb, 0xfa, 0xe1, 0xba, 0x8e, 0x4a>>
    results = STUN.encode_attribute(:xor_mapped_address, {"192.168.42.8", 51944})
    assert target == iodata_to_binary(results)
  end

  test "parse captured request" do
    {:ok, ret} = STUN.parse(stun_request_1, fn(_r) -> "755f33f22509329a49ab3d6420e947e9" end)
    assert :request == ret[:request_type]
    assert <<33, 18, 164, 66, 124, 83, 243, 18, 121, 83, 109, 153, 192, 13, 20, 77>> == ret[:transaction_id]
    assert "d7de9017:b52d0601" == ret[:username]
    assert 1853817087 == ret[:priority]
    assert 1139902001367096328 == ret[:ice_controlled]
  end

  test "parse captured request with bad fingerprint" do
    stun_request_with_bad_fingerprint = binary_part(stun_request_1, 0, iodata_size(stun_request_1) - 4) <> <<0, 0, 0, 0>>
    {:error, "bad fingerprint"} = STUN.parse(stun_request_with_bad_fingerprint, fn(_r) -> "755f33f22509329a49ab3d6420e947e9" end)
  end

  test "parse captured request with wrong password for message integrity" do
    {:error, "invalid message integrity"} = STUN.parse(stun_request_1, fn(_r) -> "foo" end)
  end

  test "parse captured response" do
    {:ok, response} = STUN.parse(stun_response_1, fn(_r) -> "755f33f22509329a49ab3d6420e947e9" end)
    assert {"192.168.42.8", 51944} = response[:mapped_address]
  end 

  test "build request" do
    {:ok, packet} = STUN.build_request(
      transaction_id: << 33, 18, 164, 66, 124, 83, 243, 18, 121, 83, 109, 153, 192, 13, 20, 77 >>,
      username: "d7de9017:b52d0601",
      priority: 1853817087,
      ice_controlled: 1139902001367096328,
      message_integrity_key: "755f33f22509329a49ab3d6420e947e9"
    )
    assert stun_request_1 == iodata_to_binary(packet)
  end

#     def testBuildAnotherRequest(self):
#         stun_request_1 = ''.join([chr(x) for x in STUN_REQUEST_1])
#         protocol = stun.STUN()
#         protocol.addCred('d7de9017:b52d0601', '755f33f22509329a49ab3d6420e947e9')
#         testPacket = protocol.buildBindingRequest({
#             'username': 'd7de9017:b52d0601',
#             'priority': 1853817087,
#             'ice_controlled': 1139902001367096328,
#             'use_candidate': None,
#         })
#         # test by trying to parse this
#         protocol.datagramReceived(testPacket, ('127.0.0.1', 4242,))

#     def testParseCapturedResponse(self):
    
#     def testBuildBindSuccessReply(self):
#         #stun_request_1 = ''.join([chr(x) for x in STUN_REQUEST_1])
#         stun_response_1 = ''.join([chr(x) for x in STUN_RESPONSE_1])
#         protocol = stun.STUN()
#         protocol.addCred('d7de9017:b52d0601', '755f33f22509329a49ab3d6420e947e9')
#         self.assertEqual( stun_response_1, protocol.buildBindSuccessReply( '!\x12\xa4B|S\xf3\x12ySm\x99\xc0\r\x14M', 'd7de9017:b52d0601', ('192.168.42.8', 51944,) ) )






  def stun_request_1 do
    # Captured from Wireshark with two Firefox 28 browser talking to each other
    <<
    0x00, 0x01, 0x00, 0x4c, 0x21, 0x12, 0xa4, 0x42,
    0x7c, 0x53, 0xf3, 0x12, 0x79, 0x53, 0x6d, 0x99,
    0xc0, 0x0d, 0x14, 0x4d, 0x00, 0x06, 0x00, 0x11,
    0x64, 0x37, 0x64, 0x65, 0x39, 0x30, 0x31, 0x37,
    0x3a, 0x62, 0x35, 0x32, 0x64, 0x30, 0x36, 0x30,
    0x31, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x04,
    0x6e, 0x7f, 0x00, 0xff, 0x80, 0x29, 0x00, 0x08,
    0x0f, 0xd1, 0xbe, 0xd4, 0xae, 0x3e, 0x1c, 0x08,
    0x00, 0x08, 0x00, 0x14, 0xae, 0xc2, 0xb0, 0x40,
    0xea, 0x55, 0x75, 0x6b, 0xfd, 0x61, 0xab, 0x4a,
    0xf8, 0x4d, 0x1e, 0x7c, 0xca, 0x36, 0x70, 0xad,
    0x80, 0x28, 0x00, 0x04, 0x7a, 0xc7, 0x0f, 0xad
    >>
  end

  def stun_response_1 do
    # Captured from Wireshark with two Firefox 28 browser talking to each other
    <<
    0x01, 0x01, 0x00, 0x2c, 0x21, 0x12, 0xa4, 0x42,
    0x7c, 0x53, 0xf3, 0x12, 0x79, 0x53, 0x6d, 0x99,
    0xc0, 0x0d, 0x14, 0x4d, 0x00, 0x20, 0x00, 0x08,
    0x00, 0x01, 0xeb, 0xfa, 0xe1, 0xba, 0x8e, 0x4a,
    0x00, 0x08, 0x00, 0x14, 0x30, 0x35, 0xe6, 0x1e,
    0xb7, 0xab, 0x88, 0x47, 0x63, 0xd3, 0x83, 0x4f,
    0x76, 0xb1, 0x8a, 0x02, 0x08, 0x66, 0x93, 0x25,
    0x80, 0x28, 0x00, 0x04, 0x4f, 0xf2, 0xf9, 0xa1
    >>
  end
end
