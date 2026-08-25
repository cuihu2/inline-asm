"""Pure mathematical and hardware-layout NTT semantics for the HPU model."""

from array import array
from collections.abc import Sequence
from math import isqrt


def _require_power_of_two(value: int, name: str) -> None:
    if value <= 0 or value & (value - 1):
        raise ValueError(f"{name} must be a positive power of two")


def _require_u32_modulus(q: int) -> None:
    if not 2 <= q <= 0xFFFF_FFFF:
        raise ValueError("modulus q must fit the uint32 HPU coefficient ABI")


def _require_canonical(values: Sequence[int], q: int, name: str) -> None:
    for index, value in enumerate(values):
        if type(value) is not int or not 0 <= value < q:
            raise ValueError(f"{name}[{index}] must be a canonical residue in [0,q)")


def bit_reverse_index(index: int, n: int) -> int:
    """Reverse the ``log2(n)`` low bits of an index in ``range(n)``."""

    _require_power_of_two(n, "n")
    if not 0 <= index < n:
        raise ValueError("index must be in range(n)")
    reversed_index = 0
    for _ in range(n.bit_length() - 1):
        reversed_index = (reversed_index << 1) | (index & 1)
        index >>= 1
    return reversed_index


def is_prime(value: int) -> bool:
    """Return whether ``value`` is prime using exact integer trial division."""

    if value < 2:
        return False
    if value % 2 == 0:
        return value == 2
    for divisor in range(3, isqrt(value) + 1, 2):
        if value % divisor == 0:
            return False
    return True


def find_ntt_prime(start: int, order: int) -> int:
    """Find the first prime at least ``start`` congruent to one modulo ``order``."""

    if order <= 0:
        raise ValueError("order must be positive")
    candidate = max(start, 2)
    candidate += (1 - candidate) % order
    while not is_prime(candidate):
        candidate += order
    return candidate


def is_primitive_2n_root(psi: int, n: int, q: int) -> bool:
    """Check the primitive ``2*n``-th root condition used by negacyclic NTT."""

    if q <= 2 or n <= 0 or n & (n - 1):
        return False
    psi %= q
    return pow(psi, n, q) == q - 1 and pow(psi, 2 * n, q) == 1


def find_primitive_2n_root(q: int, n: int) -> int:
    """Find a primitive ``2*n``-th root modulo the prime ``q``."""

    _require_power_of_two(n, "n")
    order = 2 * n
    if not is_prime(q) or (q - 1) % order:
        raise ValueError("q must be prime with 2*n dividing q-1")
    exponent = (q - 1) // order
    for base in range(2, q):
        candidate = pow(base, exponent, q)
        if is_primitive_2n_root(candidate, n, q):
            return candidate
    raise ValueError("no primitive 2*n-th root exists for q")


def _require_primitive_n_root(omega: int, n: int, q: int) -> None:
    _require_u32_modulus(q)
    if (
        not is_prime(q)
        or pow(omega, n, q) != 1
        or (n > 1 and pow(omega, n // 2, q) != q - 1)
    ):
        raise ValueError("omega must be a primitive n-th root modulo prime q")


def logical_cyclic_ntt(
    values: list[int],
    omega: int,
    q: int,
    inverse: bool = False,
) -> list[int]:
    """Compute a natural-order radix-2 cyclic NTT or inverse NTT."""

    n = len(values)
    _require_power_of_two(n, "transform length")
    _require_primitive_n_root(omega, n, q)
    active_root = pow(omega, -1, q) if inverse else omega % q
    result = [values[bit_reverse_index(position, n)] % q for position in range(n)]

    width = 2
    while width <= n:
        step = pow(active_root, n // width, q)
        for begin in range(0, n, width):
            twiddle = 1
            half_width = width // 2
            for offset in range(half_width):
                even_index = begin + offset
                odd_index = even_index + half_width
                even = result[even_index]
                odd = result[odd_index] * twiddle % q
                result[even_index] = (even + odd) % q
                result[odd_index] = (even - odd) % q
                twiddle = twiddle * step % q
        width <<= 1

    if inverse:
        n_inverse = pow(n, -1, q)
        result = [value * n_inverse % q for value in result]
    return result


def logical_negacyclic_ntt(
    values: list[int],
    psi: int,
    q: int,
    inverse: bool = False,
) -> list[int]:
    """Compute the negacyclic NTT convention used for ``Z_q[x]/(x^N+1)``."""

    n = len(values)
    _require_power_of_two(n, "transform length")
    _require_u32_modulus(q)
    if not is_primitive_2n_root(psi, n, q):
        raise ValueError("psi must be a primitive 2*n-th root modulo q")
    omega = psi * psi % q
    if not inverse:
        twist = 1
        twisted: list[int] = []
        for value in values:
            twisted.append(value * twist % q)
            twist = twist * psi % q
        return logical_cyclic_ntt(twisted, omega, q)

    coefficients = logical_cyclic_ntt(values, omega, q, inverse=True)
    psi_inverse = pow(psi, -1, q)
    twist = 1
    for index, value in enumerate(coefficients):
        coefficients[index] = value * twist % q
        twist = twist * psi_inverse % q
    return coefficients


def p_permute(registers: list[int]) -> list[int]:
    """Apply the HPU 128-register P network once."""

    if len(registers) != 128:
        raise ValueError("P network requires exactly 128 registers")
    permuted = [0] * 128
    for old_position, value in enumerate(registers):
        new_position = (old_position >> 1) | ((old_position & 1) << 6)
        permuted[new_position] = value
    return permuted


def p_inverse_permute(registers: list[int]) -> list[int]:
    """Apply the inverse of the HPU 128-register P network once."""

    if len(registers) != 128:
        raise ValueError("inverse P network requires exactly 128 registers")
    restored = [0] * 128
    for old_position in range(128):
        new_position = (old_position >> 1) | ((old_position & 1) << 6)
        restored[old_position] = registers[new_position]
    return restored


def _require_hardware_length(n: int) -> None:
    _require_power_of_two(n, "hardware transform length")
    if n < 128 or n % 128:
        raise ValueError("hardware transform length must be a multiple of 128")


def _stage_batches(n: int, stage: int) -> list[tuple[bool, int, int]]:
    m = 1 << stage
    batches: list[tuple[bool, int, int]] = []
    if m < 128:
        for base in range(0, n, 128):
            batches.append((False, base, base + 64))
        return batches
    for group in range(0, n, 2 * m):
        for offset in range(0, m, 64):
            batches.append((True, group + offset, group + m + offset))
    return batches


def _load_batch(
    values: list[int],
    batch: tuple[bool, int, int],
) -> tuple[list[int], list[int]]:
    interleaved, first, second = batch
    if not interleaved:
        positions = list(range(first, first + 128))
    else:
        positions = []
        for lane in range(64):
            positions.extend((first + lane, second + lane))
    return [values[position] for position in positions], positions


def _store_batch(values: list[int], registers: list[int], positions: list[int]) -> None:
    for position, register in zip(positions, registers, strict=True):
        values[position] = register


def hardware_ntt_layout(n: int) -> list[int]:
    """Map each final physical position to its natural-order logical NTT index."""

    _require_hardware_length(n)
    labels = list(range(n))
    for stage in range(n.bit_length() - 1):
        for batch in _stage_batches(n, stage):
            registers, positions = _load_batch(labels, batch)
            _store_batch(labels, p_permute(registers), positions)
    return labels


def generate_hardware_ntt_twiddles(n: int, omega: int, q: int) -> list[list[int]]:
    """Generate forward BF twiddles in hardware batch/lane consumption order."""

    _require_hardware_length(n)
    _require_primitive_n_root(omega, n, q)
    labels = list(range(n))
    tables: list[list[int]] = []
    for stage in range(n.bit_length() - 1):
        m = 1 << stage
        stage_twiddles: list[int] = []
        for batch in _stage_batches(n, stage):
            registers, positions = _load_batch(labels, batch)
            for lane in range(64):
                lower = registers[2 * lane]
                upper = registers[2 * lane + 1]
                if upper != lower + m:
                    raise ValueError("forward NTT lane pairing is inconsistent")
                exponent = (lower % m) * n // (2 * m)
                stage_twiddles.append(pow(omega, exponent, q))
            _store_batch(labels, p_permute(registers), positions)
        tables.append(stage_twiddles)
    return tables


def generate_hardware_intt_twiddles(n: int, omega: int, q: int) -> list[list[int]]:
    """Generate inverse BF twiddles for the hardware dual schedule."""

    _require_hardware_length(n)
    _require_primitive_n_root(omega, n, q)
    labels = hardware_ntt_layout(n)
    scales = [1] * n
    tables: list[list[int]] = []
    log_n = n.bit_length() - 1

    for inverse_stage in range(log_n):
        forward_stage = log_n - 1 - inverse_stage
        m = 1 << forward_stage
        stage_twiddles: list[int] = []
        for batch in _stage_batches(n, forward_stage):
            label_registers, positions = _load_batch(labels, batch)
            scale_registers, _ = _load_batch(scales, batch)
            label_registers = p_inverse_permute(label_registers)
            scale_registers = p_inverse_permute(scale_registers)

            for lane in range(64):
                even_index = 2 * lane
                odd_index = even_index + 1
                lower = label_registers[even_index]
                upper = label_registers[odd_index]
                if upper != lower + m:
                    raise ValueError("inverse NTT lane pairing is inconsistent")
                alpha = scale_registers[even_index]
                beta = scale_registers[odd_index]
                exponent = (lower % m) * n // (2 * m)
                forward_twiddle = pow(omega, exponent, q)
                stage_twiddles.append(alpha * pow(beta, -1, q) % q)
                scale_registers[even_index] = alpha
                scale_registers[odd_index] = alpha * forward_twiddle % q

            _store_batch(labels, label_registers, positions)
            _store_batch(scales, scale_registers, positions)
        tables.append(stage_twiddles)

    if labels != list(range(n)) or scales != [1] * n:
        raise ValueError("inverse NTT dual schedule does not restore layout and scale")
    return tables


def pntt_stage(
    values: Sequence[int],
    twiddles: Sequence[int],
    stage: int,
    q: int,
) -> array:
    """Execute one forward hardware PNTT stage on physical-order values."""

    n = len(values)
    _require_hardware_length(n)
    if not 0 <= stage < n.bit_length() - 1:
        raise ValueError("stage is outside the transform")
    if len(twiddles) != n // 2:
        raise ValueError("a PNTT stage requires exactly n/2 twiddles")
    _require_u32_modulus(q)
    _require_canonical(values, q, "values")
    _require_canonical(twiddles, q, "twiddles")

    result = list(values)
    twiddle_index = 0
    for batch in _stage_batches(n, stage):
        registers, positions = _load_batch(result, batch)
        for lane in range(64):
            even_index = 2 * lane
            odd_index = even_index + 1
            even = registers[even_index]
            odd = registers[odd_index] * twiddles[twiddle_index] % q
            twiddle_index += 1
            registers[even_index] = (even + odd) % q
            registers[odd_index] = (even - odd) % q
        _store_batch(result, p_permute(registers), positions)
    return array("I", result)


def pintt_stage(
    values: Sequence[int],
    twiddles: Sequence[int],
    inverse_stage: int,
    q: int,
) -> array:
    """Execute one inverse hardware PINTT stage on physical-order values."""

    n = len(values)
    _require_hardware_length(n)
    log_n = n.bit_length() - 1
    if not 0 <= inverse_stage < log_n:
        raise ValueError("inverse_stage is outside the transform")
    if len(twiddles) != n // 2:
        raise ValueError("a PINTT stage requires exactly n/2 twiddles")
    _require_u32_modulus(q)
    _require_canonical(values, q, "values")
    _require_canonical(twiddles, q, "twiddles")

    forward_stage = log_n - 1 - inverse_stage
    result = list(values)
    twiddle_index = 0
    for batch in _stage_batches(n, forward_stage):
        registers, positions = _load_batch(result, batch)
        registers = p_inverse_permute(registers)
        for lane in range(64):
            even_index = 2 * lane
            odd_index = even_index + 1
            even = registers[even_index]
            odd = registers[odd_index] * twiddles[twiddle_index] % q
            twiddle_index += 1
            registers[even_index] = (even + odd) % q
            registers[odd_index] = (even - odd) % q
        _store_batch(result, registers, positions)
    return array("I", result)
