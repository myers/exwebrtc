defmodule Exwebrtc.SDP do
  def password(sdp) do
    sdp_value(sdp, "a=ice-pwd:")
  end
  def username(sdp) do
    sdp_value(sdp, "a=ice-ufrag:")
  end

  defp sdp_value(sdp, prefix) do
    List.last(String.split(find_line(sdp, prefix), ":", global: true))
  end

  defp find_line(sdp, prefix) do
    sdp |> String.split("\r\n") |> Enum.find(fn line -> String.starts_with?(line, prefix) end)
  end

end
