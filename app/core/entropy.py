from pathlib import Path
import math


def calculate_entropy(file_path: str, sample_size: int = 64 * 1024) -> float:
    """
    Calculate Shannon entropy of the first sample_size bytes of a file.

    Entropy range:
    0 = very predictable data
    8 = highly random data
    """

    path = Path(file_path)

    with path.open("rb") as file:
        data = file.read(sample_size)

    if not data:
        return 0.0

    frequency = [0] * 256

    for byte in data:
        frequency[byte] += 1

    entropy = 0.0
    data_length = len(data)

    for count in frequency:
        if count == 0:
            continue

        probability = count / data_length
        entropy -= probability * math.log2(probability)

    return entropy