# циклический сдвиг влево
def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

def sha1(message):
    # Перевод в байты
    if isinstance(message, str):
        message = message.encode('utf-8')

    # Длина сообщения в битах
    ml = len(message) * 8

    # Добавляем '1' бит (чтобы отделить от добавленных нулей)
    message += b'\x80'

    # Дополняем нулями
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'

    # Добавляем длину (64 бита)
    message += ml.to_bytes(8)

    # Инициализация регистров
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # Обработка блоков
    for i in range(0, len(message), 64):
        chunk = message[i:i+64] # 64 bytes / 512 bit

        # массив сообщений для 80 раундов
        w = [0] * 80

        # из текущего блока блок
        for j in range(16):
            w[j] = int.from_bytes(chunk[j*4:(j*4)+4])

        # генерируем оставшиеся значения
        for j in range(16, 80):
            w[j] = left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)

        # иннициализируем регистры
        a, b, c, d, e = h0, h1, h2, h3, h4

        for j in range(80):
            if 0 <= j <= 19:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 5) + f + e + k + w[j]) & 0xffffffff
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        # берем только младшие 32 бита
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)
