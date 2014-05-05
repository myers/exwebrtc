defmodule Exwebrtc.STUNServer do
  use ExActor.Strict, export: :stun_server
  alias Exwebrtc.STUN, as: STUN
  alias Exwebrtc.SDP, as: SDP

  definit port_number do
    {:ok, socket} = :gen_udp.open(port_number, [:binary, {:active, :true}])
    initial_state(%{socket: socket})
  end

  defcast answer_sdp(sdp), state: state do
    state = Dict.put(state, :sdp, sdp)
    if Dict.has_key?(state, :ready_to_probe) do
      probe(state)
    end
    new_state(state)
  end
  
  def probe(%{attributes: attributes, sdp: sdp, ip_addr: ip_addr, in_port_no: in_port_no, socket: socket} = state) do
    {:ok, request} = STUN.build_request(
      ice_controlling: attributes[:ice_controlled],
      priority: attributes[:priority],
      username: reverse_username(attributes[:username]),
      use_candidate: nil,
      message_integrity_key: SDP.password(sdp)
    )
    IO.puts inspect(request)
    :gen_udp.send(socket, ip_addr, in_port_no, request)
  end

  def reverse_username(username) do
    username |> String.split(":") |> Enum.reverse() |> Enum.join(":")
  end

  definfo {:udp, socket, ip_addr, in_port_no, packet}, state: state do
    {:ok, attributes} = STUN.parse(packet, fn x -> "9b4424d9e8c5e253c0290d63328b55b3" end)
    if attributes[:request_type] == :request do      
      {:ok, reply} = STUN.build_reply(
        transaction_id: attributes[:transaction_id], 
        mapped_address: {Enum.join(tuple_to_list(ip_addr), "."), in_port_no},
        message_integrity_key: "9b4424d9e8c5e253c0290d63328b55b3",
      )
      :gen_udp.send(socket, ip_addr, in_port_no, reply)

      state = Dict.put(state, :ready_to_probe, true)
      state = Dict.put(state, :ip_addr, ip_addr)
      state = Dict.put(state, :in_port_no, in_port_no)
      state = Dict.put(state, :attributes, attributes)
      if Dict.has_key?(state, :sdp) do
        probe(state)
      end
    else
      IO.puts inspect(attributes)
      raise "got a response"
    end

    new_state(state)
  end
end