defmodule Exwebrtc.Mixfile do
  use Mix.Project

  def project do
    [app: :exwebrtc,
     version: "0.0.1",
     elixir: "~> 0.13.1",
     deps: deps]
  end

  # Configuration for the OTP application
  #
  # Type `mix help compile.app` for more information
  def application do
    [ 
      applications: [
        :cowboy,
        :crypto,
      ],
      mod: { Exwebrtc, [] }
    ]
  end

  defp deps do
    [
      { :cowboy, github: "extend/cowboy" },
      { :exactor, "~> 0.3.2" },
      { :hound, github: "HashNuke/hound" }
    ]
  end
end
