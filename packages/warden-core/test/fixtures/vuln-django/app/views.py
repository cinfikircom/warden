import hashlib, subprocess
def weak(pw): return hashlib.md5(pw.encode()).hexdigest()
def run(name): return subprocess.run("report " + name, shell=True)
def parse(s): return eval(s)
