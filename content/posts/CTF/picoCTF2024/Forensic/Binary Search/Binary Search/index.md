---
title: "picoCTF 2024 Forensic - Binary Search"
date:  2024-02-15
categories: [CTF]
tags:       [forensic]
---
import time def binary_search_game(): \# Define connection details hostname = "atlas.picoctf.net" port = 51887 username = "ctf-player" password = "83dcefb7" \# Replace this with your actual password \# Initialize the SSH client client = paramiko.SSHClient() client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) try: \# Connect to the server client.connect(hostname, port=port, username=username, password=password) ssh = client.invoke_shell() \# Read initial welcome message time.sleep(1) \# Give it a second to receive the full message ssh.recv(1024).decode('utf-8') \# Initialize the binary search range low, high = 1, 1000 while True: \# Calculate the mid-point guess = (low + high) // 2 ssh.send(f"{guess}\n") \# Wait and receive feedback from the server time.sleep(1) \# Give it a moment to process and send back the response output = ssh.recv(1024).decode('utf-8') print(output) if "Higher" in output: low = guess + 1 elif "Lower" in output: high = guess - 1 else: break \# If the feedback is neither "Higher" nor "Lower", we assume the game is over finally: \# Close the SSH connection client.close() if \_\_name\_\_ == "\_\_main\_\_": binary_search_game() 

``` line-numbers
~/CTF/picoCTF2024/forensic/Binary Search/home/ctf-player/drop-in                                            4s | 06:27:03
> python3 sol.py
500
Higher! Try again.
Enter your guess:
750
Lower! Try again.
Enter your guess:
625
Lower! Try again.
Enter your guess:
562
Higher! Try again.
Enter your guess:
593
Lower! Try again.
Enter your guess:
577
Higher! Try again.
Enter your guess:
585
Lower! Try again.
Enter your guess:
581
Congratulations! You guessed the correct number: 581
Here's your flag: picoCTF{g00d_gu355_ee8225d0}
```

flag:`picoCTF{g00d_gu355_ee8225d0}`
