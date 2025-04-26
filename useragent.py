import random

def get_useragent():
    one_set = [
        f"Lynx/{random.randint(2, 3)}.{random.randint(8, 9)}.{random.randint(0, 2)}",
        f"libwww-FM/{random.randint(2, 3)}.{random.randint(13, 15)}",
        f"w3m/{random.randint(0, 5)}.{random.randint(1, 3)}.{random.randint(0, 9)}"
    ]
    
    two_set = [
        f"Links/{random.randint(2, 3)}.{random.randint(0, 9)}.{random.randint(0, 5)}",
        f"curl/{random.randint(7, 8)}.{random.randint(50, 79)}.{random.randint(0, 9)} libcurl/{random.randint(7, 8)}.{random.randint(50, 79)}.{random.randint(0, 9)}",
        f"OpenSSL/{random.randint(1, 3)}.{random.randint(0, 4)}.{random.randint(0, 9)}"
    ]
    
    three_set = [
        f"GnuTLS/{random.randint(3, 4)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
        f"LibreSSL/{random.randint(2, 3)}.{random.randint(0, 6)}.{random.randint(0, 9)}",
        f"BoringSSL/{random.randint(0, 1)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
        f"Apache-HttpClient/{random.randint(4, 5)}.{random.randint(0, 5)}.{random.randint(0, 9)} (Java)"
    ]
    
    return f"{one_set[random.randint(0, len(one_set)-1)]} {two_set[random.randint(0, len(two_set)-1)]} {three_set[random.randint(0, len(three_set)-1)]}"


def get_useragent_experimental(file='user-agent/useragent.txt'):
    with open(file, 'r') as f:
        lines = f.readlines()
    return f'{lines[random.randint(0, len(lines)-1)].strip()}'