"""macOS diagnostics for the agent lifecycle (run by .github/workflows/macos.yml).

Creates a throwaway vault, unlocks it through `tacitty unlock` in a pty (the
way the integration tests do), then reports whether the agent survived the
CLI exiting, plus the agent's own event log (TACITTY_LOG)."""
import os, pty, select, subprocess, sys, tempfile, time

out_dir = sys.argv[1]
binp = os.path.abspath("target/debug/tacitty")
base = tempfile.mkdtemp(prefix="tdiag")
home, run = os.path.join(base, "home"), os.path.join(base, "run")
os.makedirs(home); os.makedirs(run)
log = os.path.join(out_dir, "agent-events.log")
env = dict(os.environ, HOME=home, XDG_RUNTIME_DIR=run, TACITTY_TEST_WORK_FACTOR="8", TACITTY_LOG=log)
env.pop("TACITTY_ACTIVE", None)

def in_pty(args, lines):
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(binp, [binp] + args, env)
    out = b""
    def drain(t):
        nonlocal out
        end = time.time() + t
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                try:
                    out += os.read(fd, 4096)
                except OSError:
                    return
    drain(1.0)
    for line in lines:
        os.write(fd, line.encode() + b"\r")
        drain(1.5)
    drain(1.0)
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    return status, out.decode(errors="replace")

def agents():
    return subprocess.run(["ps", "-axo", "pid,ppid,pgid,sess,tty,stat,command"], capture_output=True, text=True).stdout

report = []
for args, lines in [(["init", "--no-autostart"], ["pw-diag-123", "pw-diag-123"]),
                    (["add", "x"], ["sec", "sec", "pw-diag-123"]),
                    (["unlock"], ["pw-diag-123"])]:
    status, out = in_pty(args, lines)
    report.append(f"$ tacitty {' '.join(args)} -> status {status}\n{out}\n")
    report.append("agent processes:\n" + "\n".join(l for l in agents().splitlines() if "tacitty agent" in l) + "\n")
time.sleep(2)
report.append("after 2s:\n" + "\n".join(l for l in agents().splitlines() if "tacitty agent" in l) + "\n")
st = subprocess.run([binp, "status"], env=env, capture_output=True, text=True)
report.append(f"$ tacitty status -> {st.returncode}\n{st.stdout}{st.stderr}\n")
report.append("runtime dir listing:\n" + subprocess.run(["ls", "-laR", run], capture_output=True, text=True).stdout)
open(os.path.join(out_dir, "agent-diag.txt"), "w").write("\n".join(report))
print("\n".join(report))

# --- window size diagnostics ------------------------------------------------
import fcntl, struct, termios
lines = []
m, sl = pty.openpty()
try:
    fcntl.ioctl(m, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    lines.append("set size on plain pty master: ok")
except OSError as e:
    lines.append(f"set size on plain pty master: FAILED {e}")
lines.append("slave sees: %r" % (struct.unpack("HHHH", fcntl.ioctl(sl, termios.TIOCGWINSZ, bytes(8)))[:2],))
os.close(m); os.close(sl)

pid, fd = pty.fork()
if pid == 0:
    os.execve(binp, [binp, "shell", "--", "python3", "-c",
                     "import time,fcntl,termios,struct; time.sleep(2); "
                     "print('INNER', struct.unpack('HHHH', fcntl.ioctl(0, termios.TIOCGWINSZ, bytes(8)))[:2])"],
              dict(env, SHELL="/bin/bash"))
time.sleep(0.5)
try:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    lines.append("set size on tacitty's pty master: ok")
except OSError as e:
    lines.append(f"set size on tacitty's pty master: FAILED {e}")
out = b""
end = time.time() + 6
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.1)
    if r:
        try:
            out += os.read(fd, 4096)
        except OSError:
            break
lines.append("tacitty shell inner output: %r" % out.decode(errors="replace")[-200:])
try:
    os.waitpid(pid, 0)
except ChildProcessError:
    pass
open(os.path.join(out_dir, "winsize-diag.txt"), "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
