import subprocess

subprocess.call(["nmap", "-v", "-O", "172.16.1.2"], stdout = None, stderr = None, shell = False)
