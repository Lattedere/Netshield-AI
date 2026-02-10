def extract_features(packet):
    import random

    length = len(packet)
    feature1 = (length % 1000) / 100

    try:
        port = packet.sport if hasattr(packet, "sport") else 0
        feature2 = port % 900 + 100
    except:
        feature2 = random.randint(100, 999)

    try:
        raw = sum(bytearray(bytes(packet)))
    except:
        raw = 50

    feature3 = (raw % 480) + 20

    return [feature1, feature2, feature3]
