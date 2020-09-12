# ExSecp256k1

Rust Nif that wraps a couple functions from the [libsecp256k1](https://github.com/paritytech/libsecp256k1) rust library. It only wraps secp256k1 functions used in Ethereum.

## Installation

It's not available on hex.pm yet. So the only way to install it using this repo:

```elixir
  [
    {:ex_secp256k1, git: "https://github.com/ayrat555/ex_secp256k1"}
  ]
```

## Usage

To create a public key from a private key use `ExSecp256k1.create_public_key/1`. The result is uncompressed public key:

```elixir
{:ok, _binary} = ExSecp256k1.create_public_key(<<120, 128, 174, 201, 52, 19, 241, 23, 239, 20, 189, 78, 109, 19, 8, 117, 171, 44, 125, 125, 85, 160, 100, 250, 195, 194, 247, 189, 81, 81, 99, 128>>)

{:error, :wrong_private_key_size} = ExSecp256k1.create_public_key(<<1>>)
```

To sign a message use `ExSecp256k1.sign/2`. It returns a tuple with `{:ok, {r, s, recovery_id}}` on success and `{:error, reason_atom}` on error:
```elixir
message = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2>>
private_key = <<120, 128, 174, 201, 52, 19, 241, 23, 239, 20, 189, 78, 109, 19, 8, 117, 171, 44, 125, 125, 85, 160, 100, 250, 195, 194, 247, 189, 81, 81, 99, 128>>

{:ok {r_binary, s_binary, recovery_id_int}} = ExSecp256k1.sign(message, private_key)

{:error, :message_not_binary} = ExSecp256k1.sign(10, private_key)
```

To recover a public key from signed message use `ExSecp256k1.recover/4`:
```elixir
hash =
     <<218, 245, 167, 121, 174, 151, 47, 151, 33, 151, 48, 61, 123, 87, 71, 70, 199, 239, 131,
       234, 218, 192, 242, 121, 26, 210, 61, 185, 46, 76, 142, 83>>

r =
     <<40, 239, 97, 52, 11, 217, 57, 188, 33, 149, 254, 83, 117, 103, 134, 96, 3, 225, 161, 93,
       60, 113, 255, 99, 225, 89, 6, 32, 170, 99, 98, 118>>

s =
     <<103, 203, 233, 216, 153, 127, 118, 26, 236, 183, 3, 48, 75, 56, 0, 204, 245, 85, 201,
       243, 220, 100, 33, 75, 41, 127, 177, 150, 106, 59, 109, 131>>

recovery_id = 0

{:ok, _public_key_binary} = ExSecp256k1.recover(hash, r, s, recovery_id)
{:error, :recovery_failure} = ExSecp256k1.recover(hash, r, s, 2)
```

## Contributing

1. [Fork it!](https://github.com/ayrat555/ex_secp256k1)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
