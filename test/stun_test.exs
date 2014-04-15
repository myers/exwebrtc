defmodule STUNTest do
  use ExUnit.Case

  test "encode_xor_mapped_address" do
    # from the captured request
    target = <<0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xeb, 0xfa, 0xe1, 0xba, 0x8e, 0x4a>>
    results = Exwebrtc.STUN.encode_xor_mapped_address("192.168.42.8", 51944)
    assert target == results
  end

#     def testParseCapturedRequest(self):
#         stun_request_1 = ''.join([chr(x) for x in STUN_REQUEST_1])
#         class STUNNode(stun.STUN):
#             def requestRecieved(stunNode, request, source):
#                 self.assertEqual('!\x12\xa4B|S\xf3\x12ySm\x99\xc0\r\x14M', request['transaction_id'])
#                 self.assertEqual(16, len(request['transaction_id']))
#                 self.assertEqual('d7de9017:b52d0601', request['username'])
#                 self.assertEqual(1853817087, request['priority'])
#                 self.assertEqual(1139902001367096328, request['ice_controlled'])
#         protocol = STUNNode()
#         protocol.addCred('d7de9017:b52d0601', '755f33f22509329a49ab3d6420e947e9')
#         protocol.datagramReceived(stun_request_1, ('127.0.0.1', 4242,))

#     def testBuildRequest(self):
#         stun_request_1 = ''.join([chr(x) for x in STUN_REQUEST_1])
#         protocol = stun.STUN()
#         protocol.addCred('d7de9017:b52d0601', '755f33f22509329a49ab3d6420e947e9')
#         testPacket = protocol.buildBindingRequest({
#             'transaction_id': '!\x12\xa4B|S\xf3\x12ySm\x99\xc0\r\x14M', # normally you wouldn't pass this in
#             'username': 'd7de9017:b52d0601',
#             'priority': 1853817087,
#             'ice_controlled': 1139902001367096328
#         })
#         self.assertEqual(stun_request_1, testPacket)


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
#         stun_response_1 = ''.join([chr(x) for x in STUN_RESPONSE_1])
#         class STUNNode(stun.STUN):
#             def responseRecieved(stunNode, request, source):
#                 self.assertEqual(('192.168.42.8', 51944,), request['mapped_address'])
#         protocol = STUNNode()
#         protocol.addCred('d7de9017:b52d0601', '755f33f22509329a49ab3d6420e947e9')
#         protocol.username = 'd7de9017:b52d0601'
#         protocol.datagramReceived(stun_response_1, ('127.0.0.1', 4242,))
    
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
