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

function (prg::PRG)(i::UInt32)
    bytes = Vector{UInt8}(undef, length(prg.s) + 4)
    copyto!(bytes, prg.s)  # @inbounds
    offset = length(prg.s)
    for j in 1:4 # @inbounds
        bytes[offset + j] = (i >> (32 - 8j)) % UInt8
    end
    prg.h(bytes)
end

function Base.getindex(prg::PRG, range)
    (; start, stop) = range
    
    a = bitlength(prg.h) ÷ 8  # outlength
    start_block = div(start - 1, a)  # Remove RoundUp
    end_block = div(stop - 1, a)     # Remove -1 and RoundUp
    
    # Calculate exact required capacity
    total_blocks = end_block - start_block + 1
    r = Vector{UInt8}(undef, total_blocks * a)
    
    # Fill only the needed blocks
    for (idx, i) in enumerate(UInt32(start_block):UInt32(end_block))
        ri = prg(i)
        offset = (idx - 1) * a + 1
        r[offset:offset + length(ri) - 1] = ri
    end
    
    # Calculate the exact indices needed from the generated blocks
    start_offset = (start - 1) % a + 1
    end_offset = (stop - 1) % a + 1 + (end_block - start_block) * a
    
    return r[start_offset:end_offset]
end

struct RO
    h::HashSpec
    n_out::Int
end

# zerofirst(x, n) = (x << n) >> n # Puts first n bits of a number x to zero. 

"""
    (ro::RO)(d::AbstractVector{UInt8})

Apply a Random Oracle to the input data with specified output length.

# Arguments
- `ro::RO`: Random Oracle instance containing hash function and output length
- `d::AbstractVector{UInt8}`: Input data

# Returns
- `Vector{UInt8}`: Output bytes of specified length with appropriate bit padding

# Throws
- `ArgumentError`: If input parameters are invalid
"""
function (ro::RO)(d::AbstractVector{UInt8})
    # Destructure and validate parameters
    (; h, n_out) = ro
    
    # Calculate required output bytes
    n_bytes = cld(n_out, 8)  # Ceiling division for required bytes
    
    # Convert output length to bytes (using little-endian for Java compatibility)
    len_bytes = reinterpret(UInt8, [UInt32(n_out)])
    
    # Pre-allocate and prepare input buffer
    total_length = length(len_bytes) + length(d)
    input_buffer = Vector{UInt8}(undef, total_length)
    
    # Copy length bytes in reverse (little-endian) and data
    copyto!(input_buffer, 1, reverse(len_bytes), 1, length(len_bytes))
    copyto!(input_buffer, length(len_bytes) + 1, d, 1, length(d))
    
    # Generate PRG seed
    seed = h(input_buffer)
    prg = PRG(h, seed)
    
    # Generate output bytes
    output = prg[1:n_bytes]
    
    # Apply bit masking if necessary
    remaining_bits = mod(n_out, 8)
    if remaining_bits != 0
        # Create a mask for the remaining bits
        mask = UInt8((1 << remaining_bits) - 1)
        output[1] = output[1] & mask
    end
    
    return output
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


# Define the iterator struct
struct PRGIterator{T}
    prg::PRG
    n::Int
    M::Int  # bytes per number
end

PRGIterator{T}(prg, n) where T <: Integer = PRGIterator{T}(prg, n, div(n, 8, RoundUp))

# Iterator interface
Base.IteratorSize(::Type{<:PRGIterator}) = Base.IsInfinite()
Base.eltype(::PRGIterator{T}) where T = T

function Base.iterate(iter::PRGIterator{T}, state=1) where T
    # Calculate block indices for this number
    start_idx = (state - 1) * iter.M + 1
    end_idx = start_idx + iter.M - 1
    
    # Get bytes for this number
    bytes = iter.prg[start_idx:end_idx]
    
    # Convert to number
    number = interpret(Vector{BigInt}, bytes, 1)[1]
    
    return (number, state + 1)
end

struct ROPRG
    ρ::Vector{UInt8}
    rohash::HashSpec
    prghash::HashSpec
end

ROPRG(ρ::Vector{UInt8}, hasher::HashSpec) = ROPRG(ρ, hasher, hasher)


"""
    (roprg::ROPRG)(x::AbstractVector{UInt8})

Apply the Random Oracle Pseudorandom Generator to input bytes.

# Arguments
- `roprg::ROPRG`: The ROPRG instance containing ρ, rohash, and prghash parameters
- `x::AbstractVector{UInt8}`: Input byte vector

# Returns
- `PRG`: A Pseudorandom Generator initialized with the processed input

# Throws
- `ArgumentError`: If input validation fails
"""
function (roprg::ROPRG)(x::AbstractVector{UInt8})
    # Destructure parameters
    ρ, rohash, prghash = roprg.ρ, roprg.rohash, roprg.prghash
    
    # Calculate output length
    ns = bitlength(prghash)
    ro = RO(rohash, ns)
    
    # Pre-allocate buffer for concatenated input
    total_length = length(ρ) + length(x)
    d = Vector{UInt8}(undef, total_length)
    
    # Efficiently copy data
    copyto!(d, 1, ρ, 1, length(ρ))
    copyto!(d, length(ρ) + 1, x, 1, length(x))
    
    # Generate seed and create PRG
    s = ro(d)
    prg = PRG(prghash, s)

    return prg
end

(roprg::ROPRG)(x::String) = roprg(Vector{UInt8}(x))
(roprg::ROPRG)(x::Symbol) = roprg(string(x))

end
