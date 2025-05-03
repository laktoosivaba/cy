#!/usr/bin/env python3
"""
This utility is used to generate a topic name whose preferred subject-ID allocation is identical to that
of the given topic name.
Usage:
    ./hash_collider.py /abc/def
    ./hash_collider.py /1234
"""

import sys
import random
import string
import pycyphal

ALPHABET = string.ascii_letters + string.digits + '_-'
SUBJECT_ID_BITS = 13
SUBJECT_COUNT = 2 ** SUBJECT_ID_BITS
DYNAMIC_SUBJECT_COUNT = 6144

def topic_hash(topic_name: str) -> int:
    try:
        numeric = int(topic_name[1:])
    except ValueError:
        pass
    else:
        if (0 <= numeric < SUBJECT_COUNT) and f"/{numeric}" == topic_name:  # Only accept canonical form.
            return numeric
    return pycyphal.transport.commons.crc.CRC64WE.new(topic_name.encode()).value


def preferred_subject_id(hash: int) -> int:
    if hash < SUBJECT_COUNT:  # This is a pinned topic.
        return hash
    return hash % DYNAMIC_SUBJECT_COUNT


def find_subject_id_collision(topic_name: str, *, max_suffix_len: int) -> str:
    target_hash = topic_hash(topic_name)
    if DYNAMIC_SUBJECT_COUNT <= target_hash < SUBJECT_COUNT:
        raise ValueError(f"Topics pinned outside of the dynamic range are collision-free by design: {topic_name!r}")
    prefix = topic_name
    target_subject_id = preferred_subject_id(target_hash)
    while True:
        suffix_len = random.randint(1, max_suffix_len)
        suffix = ''.join(random.choice(ALPHABET) for _ in range(suffix_len))
        candidate = prefix + suffix
        if preferred_subject_id(topic_hash(candidate)) == target_subject_id:
            return candidate


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(f"Usage: {sys.argv[0]} <text>")
    original = sys.argv[1]
    twin = find_subject_id_collision(original, max_suffix_len=4)
    print(twin)


if __name__ == "__main__":
    main()
