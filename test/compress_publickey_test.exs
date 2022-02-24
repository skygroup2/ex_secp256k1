defmodule CompressPKTest do
  use ExUnit.Case

  test "compress" do
    pk = "04fba82ec5b769bad11eaad00244a6fdb28a106d8b157501a41b2444d2527a83c4cb570ea479030de1c2643d89549bd8f93a6d91f25f6847f748a1ed3fd9055fca"
    e = "02fba82ec5b769bad11eaad00244a6fdb28a106d8b157501a41b2444d2527a83c4"
    o = pk |> Base.decode16!(case: :lower) |> ExSecp256k1.format_public_key() |> elem(1) |> Base.encode16(case: :lower)
    assert e == o
  end

  test "decompress" do
    pk = "02fba82ec5b769bad11eaad00244a6fdb28a106d8b157501a41b2444d2527a83c4"
    e = "04fba82ec5b769bad11eaad00244a6fdb28a106d8b157501a41b2444d2527a83c4cb570ea479030de1c2643d89549bd8f93a6d91f25f6847f748a1ed3fd9055fca"
    o = pk |> Base.decode16!(case: :lower) |> ExSecp256k1.format_public_key() |> elem(1) |> Base.encode16(case: :lower)
    assert e == o
  end
end