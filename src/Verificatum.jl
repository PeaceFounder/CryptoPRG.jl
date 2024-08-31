module Verificatum

import ..CryptoPRG: bitlength, HashSpec
import Random
using Random: AbstractRNG, SamplerBigInt

# The PRG and RO is implemented according to Verificatum verifier specification. 
# It would also be valuable to implement Fips 1.4 standart in the future. 

struct PRG <: AbstractRNG
    h::HashSpec
    s::Vector{UInt8}
end

PRG(hasher::String; s = Vector{UInt8}("SEED")) = PRG(HashSpec(hasher), s)
bitlength(prg::PRG) = bitlength(prg.h)

(prg::PRG)(i::UInt32) = prg.h([prg.s..., reverse(reinterpret(UInt8, UInt32[i]))...])


function Base.getindex(prg::PRG, range)
    (; start, stop) = range
    
    a = bitlength(prg.h) ÷ 8 # outlength

    K = div(stop, a, RoundUp) - 1

    r = UInt8[]
    
    for i in UInt32(0):UInt32(K)
        ri = prg(i)
        append!(r, ri)
    end
    
    return r[range]
end


struct RO
    h::HashSpec
    n_out::Int
end

zerofirst(x, n) = (x << n) >> n # Puts first n bits of a number x to zero. 

function (ro::RO)(d::Vector{UInt8})
    (; h, n_out) = ro

    nb = reinterpret(UInt8, UInt32[n_out])
    s = h([reverse(nb)...,d...]) # Numbers on Java are represented in reverse
    prg = PRG(h, s)

    a = prg[1:div(n_out, 8, RoundUp)]
    
    if mod(n_out, 8) != 0 
        a[1] = zerofirst(a[1], 8 - mod(n_out, 8))
    end

    return a
end

_tobig(x) = parse(BigInt, bytes2hex(reverse(x)), base=16)
interpret(::Type{BigInt}, x::Vector{UInt8}) = _tobig(reverse(x))


function interpret(::Type{Vector{T}}, 𝐫::Vector{UInt8}, N::Int) where T <: Integer
    M = length(𝐫) ÷ N
    𝐮 = reshape(𝐫, (M, N))
    𝐭 = [interpret(T, 𝐮[:, i]) for i in 1:N]
    return 𝐭
end


function Base.rand(prg::PRG, ::Type{T}, N::Int; n = bitlength(T)) where T <: Integer

    M = div(n, 8, RoundUp) # bytes for each number

    total = M * N

    𝐫 = prg[1:total]
    𝐭 = interpret(Vector{BigInt}, 𝐫, N)
    
    return 𝐭
end

@deprecate Base.rand(prg::PRG, n::Int, N::Int) Base.rand(prg, BigInt, N; n) false
Base.rand(prg::PRG, ::Type{T}; n = bitlength(T)) where T <: Integer = rand(prg, T, 1; n)[1]
Base.rand(rng::PRG, sp::UnitRange{BigInt}) = rand(rng, sp, 1)[1]


function Random.rand!(rng::PRG, a::AbstractArray{T}, sp::UnitRange) where T <: Integer

    values = rand(rng, BigInt, length(a); n = bitlength(maximum(sp))) 

    a_flat = reshape(a, length(a))
    a_flat .= minimum(sp) .+ mod.(values, maximum(sp) - minimum(sp) + 1) # ToDo: fix bias (a simple skipping strategy should work)

    return a
end


struct ROPRG
    ρ::Vector{UInt8}
    rohash::HashSpec
    prghash::HashSpec
end

ROPRG(ρ::Vector{UInt8}, hasher::HashSpec) = ROPRG(ρ, hasher, hasher)

function (roprg::ROPRG)(x::Vector{UInt8})

    (; ρ, rohash, prghash) = roprg

    ns = bitlength(prghash) # outlen
    ro = RO(rohash, ns)

    d = UInt8[ρ..., x...]   

    s = ro(d)
    prg = PRG(prghash, s)
    return prg
end

(roprg::ROPRG)(x::String) = roprg(Vector{UInt8}(x))
(roprg::ROPRG)(x::Symbol) = roprg(string(x))

end
