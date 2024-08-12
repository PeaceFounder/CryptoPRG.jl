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

function bitlength(p::Integer) # For cross checking

    bits = bitstring(p)
    start = findfirst(x -> x == '1', bits)
    N = length(bits) - start + 1

    return N
end

function bitlength(p::BigInt) 

    # A dublicate is in CryptoGroups
    # It is an implementation detail within the context of package
    function _int2bytes(x::Integer)
        hex = string(x, base=16)
        if mod(length(hex), 2) != 0
            hex = string("0", hex)
        end
        
        return reverse(hex2bytes(hex))
    end

    bytes = _int2bytes(p)
    bits = bitstring(bytes[end])
    start = findfirst(x -> x == '1', bits)
    N = length(bytes) * 8  - (start - 1)

    return N
end


include("Verificatum.jl")
include("FIPS.jl")

# public FIPS, Verificatum

end # module CryptoPRG
