defmodule ExSecp256k1 do

  def sign(message, private_key) when is_binary(message) and byte_size(message) == 32 and is_binary(private_key) and byte_size(private_key) == 32 do
    case sign_nif(message, private_key) do
      {:ok, <<sig_s :: binary-size(32), sig_r :: binary-size(32), recover_id>>} ->
        {:ok, {bin32_swap(sig_s), bin32_swap(sig_r), recover_id}}
      {:error, reason} ->
        {:error, reason}
    end
  end
  def sign(message, _private_key) when is_binary(message) and byte_size(message) != 32 do
    {:error, :wrong_message_size}
  end
  def sign(_message, private_key) when is_binary(private_key) and byte_size(private_key) != 32 do
    {:error, :wrong_private_key_size}
  end
  def sign(_message, _private_key) do
    raise ArgumentError
  end

  def sign_compact(message, private_key) do
    case sign(message, private_key) do
      {:ok, {sig_s, sig_r, recover_id}} ->
        {:ok, {sig_s <> sig_r, recover_id}}
      {:error, reason} ->
        {:error, reason}
    end
  end

  def recover(hash, sig_r, sig_s, recover_id) do
    recover1(hash, sig_s, sig_r, recover_id)
  end

  def recover_compact(hash, <<sig_r :: binary-size(32), sig_s :: binary-size(32)>>, recover_id) do
    recover1(hash, sig_s, sig_r, recover_id)
  end

  defp recover1(hash, sig_s, sig_r, recover_id)
      when is_binary(hash) and byte_size(hash) == 32 and is_binary(sig_r) and byte_size(sig_r) == 32 and
           is_binary(sig_s) and byte_size(sig_s) == 32 and is_integer(recover_id) and recover_id < 4 do
    sig = bin32_swap(sig_r) <> bin32_swap(sig_s)
    case recover_nif(hash, <<sig :: binary, recover_id>>) do
      {:ok, public_key} ->
        {:ok, correct_public_key(public_key)}
      {:error, reason} ->
        {:error, reason}
    end
  end
  defp recover1(hash, _sig_s, _sig_r, _recover_id) when is_binary(hash) and byte_size(hash) != 32 do
    {:error, :wrong_hash_size}
  end
  defp recover1(_hash, sig_s, _sig_r, _recover_id) when is_binary(sig_s) and byte_size(sig_s) != 32 do
    {:error, :wrong_s_size}
  end
  defp recover1(_hash, _sig_s, sig_r, _recover_id) when is_binary(sig_r) and byte_size(sig_r) != 32 do
    {:error, :wrong_r_size}
  end
  defp recover1(_hash, _sig_s, _sig_r, recover_id) when is_integer(recover_id) and recover_id > 3 do
    {:error, :invalid_recovery_id}
  end
  defp recover1(_hash, _sig_s, _sig_r, _recover_id) do
    raise ArgumentError
  end

  def create_public_key(private_key) when is_binary(private_key) and byte_size(private_key) == 32 do
    case create_public_key_nif(private_key) do
      {:ok, public_key} ->
        {:ok, correct_public_key(public_key)}
      {:error, reason} ->
        {:error, reason}
    end
  end
  def create_public_key(private_key) when is_binary(private_key) do
    {:error, :wrong_private_key_size}
  end
  def create_public_key(_private_key) do
    raise ArgumentError
  end
  def compress_public_key(<<4, px :: binary-size(32), py :: binary-size(32)>>) do
    compress_public_key_nif(bin32_swap(px) <> bin32_swap(py))
  end
  def compress_public_key(_public_key) do
    {:error, :wrong_public_key}
  end

  defp correct_public_key(<<px :: binary-size(32), py :: binary-size(32)>>) do
    <<4>> <> bin32_swap(px) <> bin32_swap(py)
  end
  defp bin32_swap(bin) do
    value =:binary.decode_unsigned(bin, :little)
    <<value :: 256>>
  end

  # NIF
  def sign_nif(_message, _private_key), do: :erlang.nif_error(:nif_not_loaded)
  def recover_nif(_hash, _recoverable_signature), do: :erlang.nif_error(:nif_not_loaded)
  def create_public_key_nif(_private_key), do: :erlang.nif_error(:nif_not_loaded)
  def compress_public_key_nif(_public_key), do: :erlang.nif_error(:nif_not_loaded)

  @compile {:autoload, false}
  @on_load {:init, 0}

  def init() do
    case load_nif() do
      :ok ->
        :ok
      exp ->
        raise "failed to load NIF: #{inspect exp}"
    end
  end

  defp load_nif() do
    path = :filename.join(:code.priv_dir(:ex_secp256k1), 'secp256k1_nif')
    :erlang.load_nif(path, 0)
  end
end
