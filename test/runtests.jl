using Test
import CryptoPRG: bitlength

# I shall also use ndigits(..., base=2) for implementation
x = 2323535352 ## Java says 32
@test bitlength(x) == bitlength(big(x)) == 32

x = 121232 # Java says 17
@test bitlength(x) == bitlength(big(x)) == 17

x = 23235323423415352
@test bitlength(x) == bitlength(big(x)) == 55

module VerificatumTest
include("verificatum.jl")
end

