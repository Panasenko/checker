import re

def validate_ip(ip):
    ip_pattern = r'^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
    return bool(re.fullmatch(ip_pattern, ip))

def validate_sha256(hash_value):
    sha256_pattern = r'^[a-fA-F0-9]{64}$'
    return bool(re.fullmatch(sha256_pattern, hash_value))

def validate_domain(domain):
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.fullmatch(domain_pattern, domain))

# Пример использования
value = "192.168.50.123"
value1 = "9f4adc91f0b6c9fecf483393c6e4e5bda58010ebbb162e0f22358c3edb234fe3"
value2 = "google.com"
value3 = "googlecom"

# Пример использования:
# print(validate_ip(value))  # True
# print(validate_sha256(value1))  # True
# print(validate_domain(value1))  # True

def case_if(option):
    if validate_ip(option):
        return "определен ip"
    elif validate_sha256(option):
        return "Определен хеш"
    elif validate_domain(option):
        return "Определен домен"
    else:
        return "Неверный выбор"

# Пример использования
result = case_if(value3)
print(result)  # Выполнен первый кейс









