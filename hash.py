import re
def validate_hashes(hash_value):
    sha256_pattern = r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"
    return bool(re.fullmatch(sha256_pattern, hash_value))


print(validate_hashes("634438a50ae1990c4f8636801c41046"))   
