module CryptoPRG

using Nettle: hexdigest

struct HashSpec
    spec::String
end

(h::HashSpec)(x::Vector{UInt8}) = hex2bytes(hexdigest(h.spec, x))
(h::HashSpec)(x::String) = h(Vector{UInt8}(x))

# Dispatching on value types seems as plausable solution
function bitlength(h::HashSpec) 
    s = h.spec

    if s == "sha256"
        return 256
    elseif s == "sha384"
        return 384
    elseif s == "sha512"
        return 512
    else
        error("No corepsonding mapping for $x implemented")
    end
end

bitlength(::Type{T}) where T <: Integer = sizeof(T) * 8
bitlength(p::Integer) = ndigits(p, base=2)

include("Verificatum.jl")
include("FIPS.jl")

# public FIPS, Verificatum

end # module CryptoPRG
