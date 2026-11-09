"""Claude PreToolUse guard: inspect argv, never execute the supplied command.

This is a guardrail for common shell forms, not a sandbox or a full shell parser.
It does not resolve aliases, functions, variables, sourced files or generated code.
Malformed shell input gets a conservative command-position check, not a blanket ban.
"""

import json
import os
import re
import shlex
import sys


FORBIDDEN = {"pkill", "killall", "sudo", "diskutil"}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*=")
SEPARATORS = ";&|()\n"
# Protect quoted/escaped separators before shlex removes their quote provenance.
MASK = {char: chr(0xE000 + index) for index, char in enumerate(SEPARATORS)}
UNMASK = str.maketrans({value: key for key, value in MASK.items()})


def protect_quotes(script):
    result, quote, escaped, comment = [], "", False, False
    for char in script:
        if comment:
            if char != "\n":
                continue
            comment = False
        if escaped:
            result.append(MASK.get(char, char))
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = ""
            else:
                char = MASK.get(char, char)
        elif char in "\"'":
            quote = char
        elif char == "#" and (not result or result[-1] in " \t\r" + SEPARATORS):
            comment = True
            continue
        result.append(char)
    return "".join(result)


def simple_commands(script):
    lexer = shlex.shlex(protect_quotes(script), posix=True, punctuation_chars=True)
    lexer.whitespace = " \t\r"
    lexer.commenters = ""  # Comments were removed without consuming the command newline.
    lexer.wordchars += "${}:+`#"  # Variables, refspecs and xargs placeholders are words.
    # Read everything first: malformed quotes must use the fallback consistently.
    tokens = list(lexer)
    words, depth = [], 0
    for token in tokens:
        parts = list(token) if token and all(c in SEPARATORS for c in token) else [token]
        for part in parts:
            if part == "(" and words and words[-1].endswith("$"):
                words[-1] += part
                depth += 1
            elif depth:
                words[-1] += " " + part
                depth += (part == "(") - (part == ")")
            elif part and part in SEPARATORS:
                if words:
                    yield [word.translate(UNMASK) for word in words]
                    words = []
            else:
                words.append(part)
    if words:
        yield [word.translate(UNMASK) for word in words]


# Wrapper options that consume a separate value. Other flags consume one word.
WRAPPERS = {
    "env": {"-u", "--unset", "-C", "--chdir"},
    "command": set(), "nohup": set(),
    "time": {"-f", "--format", "-o", "--output"},
    "nice": {"-n", "--adjustment"}, "exec": {"-a"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "xargs": {"-a", "--arg-file", "-d", "--delimiter", "-E", "-I", "-L",
              "-n", "-P", "-s", "--eof", "--replace", "--max-lines",
              "--max-args", "--max-procs", "--max-chars"},
}


def unwrap(words):
    index, via_xargs = 0, False
    while index < len(words):
        if ASSIGNMENT.match(words[index]):
            index += 1
            continue
        name = os.path.basename(words[index])
        if name not in WRAPPERS:
            break
        via_xargs |= name == "xargs"
        index += 1
        while index < len(words) and words[index].startswith("-"):
            option = words[index]
            index += 1
            if option == "--":
                break
            if name == "command" and option in {"-v", "-V"}:
                return [], via_xargs  # Queries do not run their operand.
            if option in WRAPPERS[name]:
                index += 1
        if name == "timeout":
            index += 1  # Duration, after any timeout options.
    return words[index:], via_xargs


def git_rule(args):
    index = 0
    while index < len(args) and args[index].startswith("-"):
        index += 2 if args[index] in {"-C", "-c", "--git-dir", "--work-tree"} else 1
    if index >= len(args) or args[index] != "push":
        return None
    positional, has_remote, options = [], False, True
    index += 1
    while index < len(args):
        word = args[index]
        index += 1
        if options and word == "--":
            options = False
        elif options and word.startswith("-"):
            if (word in {"--force", "--mirror", "--force-with-lease"}
                    or word.startswith("--force-with-lease=")
                    or (not word.startswith("--") and "f" in word[1:])):
                return "force push"
            if word in {"--repo", "--receive-pack", "--exec", "-o", "--push-option"}:
                has_remote |= word == "--repo"
                index += 1
            has_remote |= word.startswith("--repo=")
        else:
            positional.append(word)
    for ref in positional:
        if ref.startswith("+"):
            return "force push"
    for ref in positional[0 if has_remote else 1:]:
        if ref.rsplit(":", 1)[-1] in {"main", "refs/heads/main"}:
            return "direct push to main"
    return None


def command_rule(words, depth, via_xargs):
    words, wrapped_xargs = unwrap(words)
    via_xargs |= wrapped_xargs
    if not words:
        return None
    name, args = os.path.basename(words[0]), words[1:]
    if name in FORBIDDEN:
        return name
    if name == "kill" and (via_xargs or any("$(" in arg or "`" in arg for arg in args)):
        return "kill through xargs" if via_xargs else "kill of a computed PID list"
    if name == "docker" and "prune" in args:
        return "docker prune"
    if name == "rm":
        recursive, targets, options = False, [], True
        for arg in args:
            if options and arg == "--":
                options = False
            elif options and arg.startswith("-"):
                recursive |= arg == "--recursive" or (
                    not arg.startswith("--") and bool(set(arg[1:]) & {"r", "R"}))
            else:
                if arg:  # An empty quoted argument is not the filesystem root.
                    targets.append(arg.rstrip("/"))
        roots = {"", "/*", "~", "~/*", "$HOME", "${HOME}", "$HOME/*", "${HOME}/*",
                 "/Users", "/Users/*", "/Volumes", "/Volumes/*"}
        if recursive and roots.intersection(targets):
            return "rm -r of a root, home or volume path"
    if name == "git":
        return git_rule(args)
    if name == "eval":
        return check(" ".join(args), depth + 1, via_xargs)
    if name in {"bash", "sh", "zsh"}:
        for index, arg in enumerate(args):
            if arg == "--" or not arg.startswith("-"):
                break
            if not arg.startswith("--") and "c" in arg and index + 1 < len(args):
                return check(args[index + 1], depth + 1, via_xargs)
    return None


def check(script, depth=0, via_xargs=False):
    if depth > 40:
        return "shell recursion limit"
    try:
        commands = list(simple_commands(script))
    except ValueError:
        # Best effort only: look for forbidden executable names at command boundaries.
        match = re.search(
            r"(?:^|[;&|()\n])\s*(?:[A-Za-z_]\w*=\S+\s+)*"
            r"(?:[^\s;&|()\"']*/)?(pkill|killall|sudo|diskutil)(?=\s|[;&|()]|$)",
            script,
        )
        return match[1] if match else None
    for words in commands:
        rule = command_rule(words, depth, via_xargs)
        if rule:
            return rule
    return None


def main():
    payload = json.load(sys.stdin)
    rule = check(payload.get("tool_input", {}).get("command", ""))
    if rule:
        print(f"Blocked by command guard: {rule} (see AGENTS.md, Rules).", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
