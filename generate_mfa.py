with open("mfa_codes.txt", "w") as f:
    for i in range(10000):
        f.write(str(i).zfill(4) + "\n")