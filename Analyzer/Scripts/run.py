import subprocess
subprocess.run(["python3", "./AccessControl/AccessControl.py", "log.jsonl"], check=True)
subprocess.run(["python3", "./CodeInjection/CodeInjection.py", "log.jsonl"], check=True)
subprocess.run(["python3", "./ForkBomb/ForkBomb.py", "log.jsonl"], check=True)
subprocess.run(["python3", "./InformationLeakage/InformationLeakage.py", "log.jsonl"], check=True)
subprocess.run(["python3", "./MemoryCorruption/MemoryCorruption.py", "log.jsonl"], check=True)
subprocess.run(["python3", "./RaceCondition/RaceCondition.py", "log.jsonl"], check=True)