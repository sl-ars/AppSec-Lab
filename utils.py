import base64
import pickle

def deserialize(data_b64: str):
    raw = base64.b64decode(data_b64)
    return pickle.loads(raw)  # arbitrary code execution