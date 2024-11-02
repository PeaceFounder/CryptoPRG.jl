using Test
using CryptoPRG.Verificatum: HashSpec, PRG, RO, PRGIterator

h = HashSpec("sha256")

s = hex2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
prg = PRG(h, s)

@test bytes2hex(prg[1:128]) == "70f4003d52b6eb03da852e93256b5986b5d4883098bb7973bc5318cc66637a8404a6950a06d3e3308ad7d3606ef810eb124e3943404ca746a12c51c7bf7768390f8d842ac9cb62349779a7537a78327d545aaeb33b2d42c7d1dc3680a4b23628627e9db8ad47bfe76dbe653d03d2c0a35999ed28a5023924150d72508668d244"

@test bytes2hex(prg[400:500]) == "cacbc062fcdbb035c9a5635a71bae6cc371d5e3cc78527a790d05a9ddf59ee9741811b7f02f02ac94ada7f65950d77766661dcb2cc2e3ee337c7e1c9254029eb3e6b6a34105605bbc61d30295f5f85df398024a65a9831ea1e26a0a9caf05aa9765324e322"

prgiterator = PRGIterator{BigInt}(prg, 100)
@test [n for (i, n) in zip(1:100, prgiterator)] == rand(prg, BigInt, 100; n = 100)

# As can be found on page 36 in:
# Wikstrom, “How To Implement A Stand-Alone Veriﬁer for the Veriﬁcatum Mix-Net.”
ro = RO(h, 65)
d = hex2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
@test bytes2hex(ro(d)) == "001a8d6b6f65899ba5"

ro = RO(h, 261)
d = hex2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
@test bytes2hex(ro(d)) == "1c04f57d5f5856824bca3af0ca466e283593bfc556ae2e9f4829c7ba8eb76db878"

