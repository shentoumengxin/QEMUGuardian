import os

STATE_FILES = [
    '/tmp/fork_bomb.state.json',
    '/tmp/information_leakage.state.json',
    '/tmp/race_condition.state.json',
    '/tmp/reverse_shell.state.json',
    '/tmp/abnormal_signal.state.json',
]

def initialize_state_files():
    for file_path in STATE_FILES:
        if os.path.exists(file_path):
            os.remove(file_path)

if __name__ == '__main__':
    initialize_state_files()