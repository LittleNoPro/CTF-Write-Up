#!/usr/bin/env python3
"""
sol.py - robust client for impossible-sudoku challenge

Features:
 - Extracts puzzle from server index (if available) or uses fallback.
 - Models preset-equality as group variables and solves by backtracking.
 - Produces a full 9x9 assignment where:
     * each row/col/3x3 contains digits 1..9
     * all cells that had same original preset value share the same assigned digit
 - Builds per-cell nonces and commitments (sha256("{nonce}-{value}"))
 - Supports both "vulnerable" (commitments each round) and "patched" (initial_commitments with server session_salt) flows.
 - Reveals exactly the cells server expects (mirror server logic).
"""
import argparse
import copy
import hashlib
import json
import random
import re
import string
import sys
import time
from collections import defaultdict

import requests
import socketio

# -------------------------
# Globals
# -------------------------
sio = socketio.Client(logger=False, reconnection=True)
URL = None

# If cannot fetch puzzle from server, fallback to this (but fallback may be unsolvable)
FALLBACK_PUZZLE = [
    [0, 7, 0, 0, 0, 6, 0, 0, 0],
    [9, 0, 0, 0, 0, 0, 0, 4, 1],
    [0, 0, 8, 0, 0, 9, 0, 5, 0],
    [0, 9, 0, 0, 0, 7, 0, 0, 2],
    [0, 0, 3, 0, 0, 0, 8, 0, 0],
    [4, 0, 0, 8, 0, 0, 0, 1, 0],
    [0, 8, 0, 3, 0, 0, 9, 0, 0],
    [1, 6, 0, 0, 0, 0, 0, 0, 7],
    [0, 0, 0, 5, 0, 0, 0, 8, 0]
]

puzzle_template = None
session_salt = None
server_sent_session_salt = False

# Solution assignment (permuted values we will reveal)
assignment = [[0]*9 for _ in range(9)]

# Grouping: map original preset value v -> list of positions (i,j)
preset_groups = defaultdict(list)

# Variables to set: we will create variables for each preset group (if any) and for each non-preset cell
# Represent variables by keys: ("G", v) for group of value v, ("C", i, j) for individual cell
variables = []      # list of variable keys
domains = {}        # var_key -> set of possible digits (1..9)
var_positions = {}  # var_key -> list of positions covered by this var (one or more)

# final mapping from positions to assigned digit, and per-cell nonces/commits
per_cell_nv = {}    # idx -> (nonce, value)
per_cell_commits = []  # flat list of 81 hex strings

# -------------------------
# Helpers
# -------------------------
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def rand_nonce(n=22):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(n))

# -------------------------
# Extract puzzle from index HTML
# -------------------------
def fetch_puzzle_from_index(url):
    global puzzle_template
    try:
        r = requests.get(url, timeout=4)
        text = r.text
        # try to find a 9x9 array in the HTML/JS
        idx = text.find('puzzle')
        if idx == -1:
            idx = text.find('[')
            if idx == -1:
                return False
        start = text.find('[', idx)
        if start == -1:
            return False
        depth = 0
        end = -1
        for pos in range(start, len(text)):
            ch = text[pos]
            if ch == '[':
                depth += 1
            elif ch == ']':
                depth -= 1
                if depth == 0:
                    end = pos
                    break
        if end == -1:
            return False
        candidate = text[start:end+1]
        candidate = candidate.replace('\n', ' ')
        puzzle_template = json.loads(candidate)
        # validate
        if (isinstance(puzzle_template, list) and len(puzzle_template) == 9 and
            all(isinstance(r, list) and len(r) == 9 for r in puzzle_template)):
            print("[*] extracted puzzle from index")
            return True
        puzzle_template = None
        return False
    except Exception:
        puzzle_template = None
        return False

# -------------------------
# Build preset groups from puzzle
# -------------------------
def build_preset_groups(puzzle):
    preset_groups.clear()
    for i in range(9):
        for j in range(9):
            v = puzzle[i][j]
            if isinstance(v, str) and v.isdigit():
                v = int(v)
            if v and v != 0:
                preset_groups[v].append((i, j))
    # Detect early impossible: any group having two positions in same row / col / block => impossible
    for v, positions in preset_groups.items():
        # check same row
        rows = defaultdict(int)
        cols = defaultdict(int)
        boxes = defaultdict(int)
        for (i,j) in positions:
            rows[i] += 1
            cols[j] += 1
            boxes[(i//3,j//3)] += 1
            if rows[i] > 1 or cols[j] > 1 or boxes[(i//3,j//3)] > 1:
                # group appears twice in same row/col/box -> cannot assign unique digits in that row/col/box
                return False, f"group value {v} appears multiple times in same row/col/box (impossible constraint)"
    return True, None

# -------------------------
# Build variable model and domains
# -------------------------
def build_variables(puzzle):
    variables.clear()
    domains.clear()
    var_positions.clear()
    # Group variables for each preset value present
    for v, positions in preset_groups.items():
        key = ("G", v)
        variables.append(key)
        domains[key] = set(range(1,10))
        var_positions[key] = list(positions)
    # Individual vars for non-preset cells
    for i in range(9):
        for j in range(9):
            if puzzle[i][j] == 0:
                key = ("C", i, j)
                variables.append(key)
                domains[key] = set(range(1,10))
                var_positions[key] = [(i,j)]
    # Pre-reduce domains using row/col/box preset interactions:
    # For example, if a group occupies a row and another group also occupies entire row? We'll keep simple pruning here.
    return

# -------------------------
# Constraint helpers
# -------------------------
def peers_of_position(i,j):
    peers = set()
    for k in range(9):
        peers.add((i,k))
        peers.add((k,j))
    br, bc = 3*(i//3), 3*(j//3)
    for r in range(br, br+3):
        for c in range(bc, bc+3):
            peers.add((r,c))
    peers.discard((i,j))
    return peers

# Check whether current partial assignment (assign_map: var_key->value) is consistent
def check_consistency(assign_map):
    # Build position->value map for assigned variables
    pos_val = {}
    for var, val in assign_map.items():
        for (i,j) in var_positions[var]:
            pos_val[(i,j)] = val
    # Row/col/box uniqueness: for any row, among assigned positions, no duplicate values
    for i in range(9):
        seen = {}
        for j in range(9):
            if (i,j) in pos_val:
                v = pos_val[(i,j)]
                if v in seen:
                    return False
                seen[v] = True
    for j in range(9):
        seen = {}
        for i in range(9):
            if (i,j) in pos_val:
                v = pos_val[(i,j)]
                if v in seen:
                    return False
                seen[v] = True
    for br in range(3):
        for bc in range(3):
            seen = {}
            for r in range(br*3, br*3+3):
                for c in range(bc*3, bc*3+3):
                    if (r,c) in pos_val:
                        v = pos_val[(r,c)]
                        if v in seen:
                            return False
                        seen[v] = True
    return True

# Get list of unassigned variables (from variables list) given assign_map
def select_unassigned_var(assign_map):
    # MRV heuristic: choose var with smallest remaining domain (after removing values already present in row/col/box)
    best = None
    best_size = 999
    for var in variables:
        if var in assign_map:
            continue
        # compute effective domain (prune by already used values in rows/cols/boxes for each position)
        dom = domains[var].copy()
        for (i,j) in var_positions[var]:
            # remove values already assigned in row/col/box positions
            # find values used in row
            used = set()
            for k in range(9):
                # check assigned variables that cover (i,k)
                for av, val in assign_map.items():
                    if (i,k) in var_positions[av]:
                        used.add(val)
                # also check positions assigned by same var_positions? covered above
            # column
            for k in range(9):
                for av, val in assign_map.items():
                    if (k,j) in var_positions[av]:
                        used.add(val)
            # box
            br, bc = 3*(i//3), 3*(j//3)
            for r in range(br, br+3):
                for c in range(bc, bc+3):
                    for av, val in assign_map.items():
                        if (r,c) in var_positions[av]:
                            used.add(val)
            dom = dom - used
        size = len(dom)
        if size < best_size:
            best_size = size
            best = var
            if best_size == 0:
                break
    return best

# -------------------------
# Backtracking search
# -------------------------
def backtrack_solve(assign_map):
    # If all variables assigned -> success
    if len(assign_map) == len(variables):
        # produce full assignment grid
        # verify full grid has 1..9 in all rows/cols/boxes
        if not check_consistency(assign_map):
            return None
        grid = [[0]*9 for _ in range(9)]
        for var, val in assign_map.items():
            for (i,j) in var_positions[var]:
                grid[i][j] = val
        # check completeness
        for i in range(9):
            if set(grid[i]) != set(range(1,10)):
                return None
        for j in range(9):
            if set(grid[r][j] for r in range(9)) != set(range(1,10)):
                return None
        for br in range(3):
            for bc in range(3):
                vals = []
                for r in range(br*3, br*3+3):
                    for c in range(bc*3, bc*3+3):
                        vals.append(grid[r][c])
                if set(vals) != set(range(1,10)):
                    return None
        return grid

    var = select_unassigned_var(assign_map)
    if var is None:
        return None
    # compute effective domain for this var (prune by used values in peers)
    dom = list(domains[var])
    random.shuffle(dom)
    for val in dom:
        assign_map[var] = val
        # quick consistency check
        if check_consistency(assign_map):
            res = backtrack_solve(assign_map)
            if res is not None:
                return res
        del assign_map[var]
    return None

# -------------------------
# Build per-cell nonces & commits from assignment grid
# -------------------------
def build_commits_from_assignment(grid):
    global per_cell_nv, per_cell_commits
    per_cell_nv = {}
    commits = []
    for i in range(9):
        for j in range(9):
            idx = i*9 + j
            val = int(grid[i][j])
            nonce = rand_nonce()
            per_cell_nv[idx] = (nonce, val)
            commits.append(sha256_hex(f"{nonce}-{val}"))
    per_cell_commits = commits
    return commits

# -------------------------
# Mirror server's get_cells_to_verify
# -------------------------
def get_cells_to_verify(verify_type, segment, puzzle):
    dim = 9
    sdim = 3
    main_only = []
    revealed_presets = set()

    if verify_type == 'row':
        for j in range(dim):
            i = segment
            if puzzle[i][j] != 0:
                revealed_presets.add(puzzle[i][j])
            main_only.append({'i': i, 'j': j})
    elif verify_type == 'column':
        for i in range(dim):
            j = segment
            if puzzle[i][j] != 0:
                revealed_presets.add(puzzle[i][j])
            main_only.append({'i': i, 'j': j})
    elif verify_type == 'square':
        p = (segment // sdim) * sdim
        q = (segment % sdim) * sdim
        for i in range(p, p+sdim):
            for j in range(q, q+sdim):
                if puzzle[i][j] != 0:
                    revealed_presets.add(puzzle[i][j])
                main_only.append({'i': i, 'j': j})
    elif verify_type == 'preset':
        for i in range(9):
            for j in range(9):
                if puzzle[i][j] != 0:
                    main_only.append({'i': i, 'j': j})
    all_cells = list(main_only)
    if verify_type != 'preset':
        for i in range(9):
            for j in range(9):
                if any(c['i'] == i and c['j'] == j for c in main_only):
                    continue
                if puzzle[i][j] in revealed_presets:
                    all_cells.append({'i': i, 'j': j})
    return {'all': all_cells, 'mainOnly': main_only, 'revealedPresets': list(revealed_presets)}

# -------------------------
# SocketIO handlers
# -------------------------
@sio.event
def connect():
    print("[*] connected to server")

@sio.event
def disconnect(*args):
    print("[*] disconnected")
    try:
        sys.exit(0)
    except SystemExit:
        pass

@sio.on('verification_started')
def handler_verification_started(data):
    global session_salt, server_sent_session_salt
    print("[*] verification_started:", data)
    if 'session_salt' in data:
        session_salt = data['session_salt']
        server_sent_session_salt = True
        print("[*] detected session_salt -> patched flow")
    else:
        server_sent_session_salt = False

@sio.on('commitment_request')
def handler_commitment_request(data):
    print("[*] server requested commitments round", data.get('round'))
    if not per_cell_commits:
        print("[!] no per_cell_commits available")
        sio.emit('error', {'message': 'no_commits'})
        return
    sio.emit('commitment_submission', {'commitments': per_cell_commits})
    print("[*] commitment_submission sent")

@sio.on('challenge')
def handler_challenge(data):
    print("[*] challenge:", data)
    if 'type' not in data:
        print("[!] malformed challenge")
        return
    vtype = data['type']
    seg = data.get('segment', 0)
    cells = get_cells_to_verify(vtype, seg, puzzle_template)
    revealed = []
    for cell in cells['all']:
        i = cell['i']; j = cell['j']
        idx = i*9 + j
        if idx in per_cell_nv:
            nonce, val = per_cell_nv[idx]
        else:
            # shouldn't happen
            nonce = rand_nonce()
            val = int(assignment[i][j]) if assignment[i][j] != 0 else random.randint(1,9)
            per_cell_nv[idx] = (nonce, val)
        revealed.append({'i': i, 'j': j, 'value': int(val), 'nonce': nonce})
    sio.emit('revelation_submission', {'revealed': revealed})
    print(f"[*] revelation_submission sent: {len(revealed)} cells")

@sio.on('verification_round_result')
def handler_round_result(data):
    print("[*] round result:", data)

@sio.on('verification_complete')
def handler_verification_complete(data):
    print("[*] verification_complete:", data)
    if data.get('success') and 'flag' in data:
        print("\n*** FLAG:", data['flag'], "***\n")
    try:
        sio.disconnect()
    except Exception:
        pass

@sio.on('error')
def handler_error(data):
    print("[!] server error:", data)

# -------------------------
# Main
# -------------------------
def main():
    global URL, puzzle_template, assignment, variables, domains, var_positions, per_cell_commits

    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True, help='Server base URL e.g. http://127.0.0.1:5000')
    args = parser.parse_args()
    URL = args.url.rstrip('/')

    # step 1: fetch puzzle
    ok = fetch_puzzle_from_index(URL)
    if not ok:
        print("[*] could not extract puzzle from index; using fallback puzzle")
        puzzle_template_local = copy.deepcopy(FALLBACK_PUZZLE)
        puzzle_template = puzzle_template_local
    else:
        # ensure ints
        for i in range(9):
            for j in range(9):
                if isinstance(puzzle_template[i][j], str) and puzzle_template[i][j].isdigit():
                    puzzle_template[i][j] = int(puzzle_template[i][j])

    # build preset groups and check early impossibility
    ok2, reason = build_preset_groups(puzzle_template)
    if not ok2:
        print("[!] preset groups create impossible constraints:", reason)
        print("[!] aborting (cannot produce consistent assignment respecting preset-group equality)")
        return

    # build variables and domains
    build_variables(puzzle_template)

    # backtracking solve to obtain assignment that satisfies both row/col/box uniqueness
    print("[*] solving for an assignment consistent with preset-group equality...")
    assign_map = {}
    solution = backtrack_solve(assign_map)
    if solution is None:
        print("[!] failed to find a full assignment satisfying constraints. Aborting.")
        return

    # we have solution grid
    assignment = solution
    print("[*] found assignment (permuted grid)")

    # build per-cell commits
    per_cell_commits = build_commits_from_assignment(assignment)
    print("[*] built per-cell commitments")

    # connect and start socket flow
    print("[*] connecting to", URL)
    sio.connect(URL, namespaces=['/'])

    # send start_verification
    sio.emit('start_verification', {'solution': assignment})

    # wait shortly for verification_started
    time.sleep(1.0)
    if server_sent_session_salt and session_salt:
        # compute root and send initial_commitments
        root = sha256_hex(session_salt + ''.join(per_cell_commits))
        print("[*] sending initial_commitments (patched flow)")
        sio.emit('initial_commitments', {'commitments': per_cell_commits, 'root_commitment': root})
    else:
        print("[*] server did not request session_salt -> will respond to per-round commitment_request")

    try:
        while sio.connected:
            time.sleep(0.5)
    except KeyboardInterrupt:
        try:
            sio.disconnect()
        except Exception:
            pass

if __name__ == '__main__':
    main()


# crew{1_gu3ss_1t_w@s_p0zz1bl3_@!!_@l0ng}