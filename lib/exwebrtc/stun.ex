defmodule Exwebrtc.STUN do
  use Bitwise

  @magic_cookie << 33, 18, 164, 66 >>
  @fingerprint_mask 0x5354554e

  @attributes_id_to_name %{
    0x0001 => :mapped_address,
    0x0002 => :response_address,
    0x0003 => :change_request,
    0x0004 => :source_address,
    0x0005 => :changed_address,
    0x0006 => :username,
    0x0007 => :password,
    0x0008 => :message_integrity,
    0x0009 => :error_code,
    0x000a => :unknown_attributes,
    0x000b => :reflected_from,
    0x0020 => :xor_mapped_address,
    0x8028 => :fingerprint,
    0x8022 => :software,
    0x8023 => :alternate_server,
    # from https://tools.ietf.org/html/rfc5245
    0x0024 => :priority,
    0x0025 => :use_candidate,
    0x8029 => :ice_controlled,
    0x802a => :ice_controlling,
  }
  @attributes_name_to_id Enum.reduce(@attributes_id_to_name, %{}, fn({k, v}, acc) -> Dict.put(acc, v, k) end)
  @request_type_id_to_name %{
    0x0001 => :request,
    0x0101 => :response,
    0x0111 => :error,
  }
  @request_type_name_to_id Enum.reduce(@request_type_id_to_name, %{}, fn({k, v}, acc) -> Dict.put(acc, v, k) end)

  def parse(packet, hmac_key_callback) do
    try do
      results = %{}
      << request_type_id :: size(16), attributes_size :: size(16), transaction_id :: [binary, size(16)], attributes :: binary >> = packet
      results = Dict.put(results, :attributes_size, attributes_size)
      results = Dict.put(results, :request_type, @request_type_id_to_name[request_type_id])
      results = Dict.put(results, :transaction_id, transaction_id)
      if attributes_size != iodata_size(attributes) do
        raise "attributes size is incorrect, garbled packet?"
      end
      results = parse_attributes(results, binary_part(attributes, 0, attributes_size))

      if Dict.has_key?(results, :fingerprint) do
        verify_fingerprint(packet, results[:fingerprint])
      end
      if Dict.has_key?(results, :message_integrity) do
        verify_message_integrity(packet, results, hmac_key_callback)
      end
      {:ok, results}
    rescue
      e in RuntimeError -> {:error, e.message}
    end
  end

  def build_request(attribs) do
    transaction_id = if Dict.has_key?(attribs, :transaction_id) do
      attribs[:transaction_id]
    else
      [@magic_cookie, :crypto.rand_bytes(12)]
    end
    header = [<< @request_type_name_to_id[:request] :: size(16)>>, << 0 :: size(16) >>, transaction_id]

    attribute_order = [:username, :use_candidate, :priority, :ice_controlling, :ice_controlled]
    attributes = Enum.map(attribute_order, fn(attrib_name) ->
      if Dict.has_key?(attribs, attrib_name) do
        encode_attribute(attrib_name, Dict.get(attribs, attrib_name))
      end
    end) |> Enum.reject(&is_atom/1)

    if Dict.has_key?(attribs, :message_integrity_key) do
      [header, attributes] = add_message_integrity(attribs[:message_integrity_key], header, attributes)
    end
    packet = add_fingerprint(header, attributes)
    {:ok, packet}
  end

  def add_fingerprint(header, attributes) do
    header = List.replace_at(header, 1, << iodata_size(attributes) + 8 :: size(16) >>)
    attributes = attributes ++ [encode_attribute(:fingerprint, [header, attributes])]
    [header, attributes]
  end

  def add_message_integrity(key, header, attributes) do
    header = List.replace_at(header, 1, << iodata_size(attributes) + 24 :: size(16) >>)
    packet_mac = :crypto.hmac(:sha, key, iodata_to_binary([header, attributes]))
    attributes = attributes ++ [encode_attribute(:message_integrity, packet_mac)]
    [header, attributes]
  end

  def build_reply(attribs) do
    if !Dict.has_key?(attribs, :transaction_id) do
      raise "must supply transaction_id"
    end

    header = [<< @request_type_name_to_id[:response] :: size(16)>>, << 0 :: size(16) >>, attribs[:transaction_id]]

    attributes = [encode_attribute(:xor_mapped_address, attribs[:mapped_address])]
    if Dict.has_key?(attribs, :message_integrity_key) do
      [header, attributes] = add_message_integrity(attribs[:message_integrity_key], header, attributes)
    end
    packet = add_fingerprint(header, attributes)
    {:ok, packet}
  end

  def string_xor(s1, s2) do
    s1 = bitstring_to_list(s1)
    s2 = bitstring_to_list(s2)
    Enum.zip(s1, s2) |> Enum.map(fn {a, b} -> a^^^b end) |> iodata_to_binary
  end

  def ip_address_to_binary(ip_addr) do
    {:ok, {a, b, c, d}} = ip_addr |> to_char_list |> :inet.parse_address
    iodata_to_binary([a, b, c, d])
  end

  def encode_attribute(:priority, value) do
    encode_attribute_header(:priority, << value :: size(32) >>)
  end
  def encode_attribute(:fingerprint, value) do
    value = :erlang.crc32(value) ^^^ @fingerprint_mask
    encode_attribute_header(:fingerprint, << value :: size(32) >>)
  end
  def encode_attribute(:ice_controlled, value) do
    encode_attribute_header(:ice_controlled, << value :: size(64) >>)
  end
  def encode_attribute(:ice_controlling, value) do
    encode_attribute_header(:ice_controlling, << value :: size(64) >>)
  end
  def encode_attribute(:xor_mapped_address, {ip_addr, port}) do
    ip_addr = ip_addr |> ip_address_to_binary |> string_xor(@magic_cookie)
    family = <<1 :: size(16)>>
    port = <<port :: size(16) >> |> string_xor(@magic_cookie)
    encode_attribute_header(:xor_mapped_address, [family, port, ip_addr])
  end
  def encode_attribute(attr_type, value) do
    encode_attribute_header(attr_type, value)
  end

  def padding_size(attribute_size) do
    (4 * Float.ceil(attribute_size / 4)) - attribute_size
  end

  def padding(attribute_size) do
    List.duplicate(0, padding_size(attribute_size))
  end

  def encode_attribute_header(attr_type, nil) do
    [<< @attributes_name_to_id[attr_type] :: size(16) >>, << 0 :: size(16) >>]
  end
  def encode_attribute_header(attr_type, value) do
    attribute_size = iodata_size(value)
    [<< @attributes_name_to_id[attr_type] :: size(16) >>, << attribute_size :: size(16) >>, value, padding(attribute_size)]
  end
  
  def parse_attributes(results, << attribute_id :: size(16), attribute_size :: size(16), rest :: binary >>) do
    ps = padding_size(attribute_size)
    << value :: [binary, size(attribute_size)], _padding :: [binary, size(ps)], next_attribute :: binary >> = rest
    value = parse_attribute_value(@attributes_id_to_name[attribute_id], value)
    if value do
      key = if @attributes_id_to_name[attribute_id] == :xor_mapped_address do
        :mapped_address
      else
        @attributes_id_to_name[attribute_id]
      end
      results = Dict.put(results, key, value)
    end
    parse_attributes(results, next_attribute)
  end
  def parse_attributes(results, ""), do: results

  def parse_attribute_value(:username, value), do: value
  def parse_attribute_value(:priority, << value :: size(32) >> ), do: value
  def parse_attribute_value(:ice_controlled, << value :: size(64) >>), do: value
  def parse_attribute_value(:ice_controlling, << value :: size(64) >>), do: value

  def parse_attribute_value(:xor_mapped_address, value) do
    <<family :: size(16), port :: [binary, size(2)], ip_addr :: [binary, size(4)] >> = value
    if family != 1 do
      raise "IPv6 not supported"
    end
    ip_addr = ip_addr |> string_xor(@magic_cookie)
    << a :: size(8), b :: size(8), c :: size(8), d :: size(8) >> = ip_addr
    port = port |> string_xor(@magic_cookie)
    << port :: size(16) >> = port
    {"#{a}.#{b}.#{c}.#{d}", port}
  end
  def parse_attribute_value(_name, value), do: value

  def verify_fingerprint(packet, << fingerprint :: size(32) >>) do
    packet_crc32 = :erlang.crc32(binary_part(packet, 0, iodata_size(packet) - 8)) ^^^ @fingerprint_mask
    if packet_crc32 != fingerprint do
      raise "bad fingerprint"
    end
  end

  def verify_message_integrity(packet, results, hmac_key_callback) do
    # change the length in header
    adjusted_attribs_size = results[:attributes_size] - 8
    packet_for_hmac_check = binary_part(packet, 0, 2) <> << adjusted_attribs_size :: size(16) >> <> binary_part(packet, 4, iodata_size(packet) - 4 - 8 - 24)

    # compute mac
    hmac_key = hmac_key_callback.(results)
    packet_mac = :crypto.hmac(:sha, hmac_key, packet_for_hmac_check)
    if packet_mac != results[:message_integrity] do
      raise "invalid message integrity"
    end
  end
  
end
