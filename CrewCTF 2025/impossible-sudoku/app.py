from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room
import hashlib
import random
import json
import os
import secrets

app = Flask(__name__)
# Always use a secure random key
app.config['SECRET_KEY'] = secrets.token_hex(16)
socketio = SocketIO(app, cors_allowed_origins="*")

# Secret contact information revealed after successful verification
# Read from environment variable with fallback to the hardcoded value
FLAG = os.environ.get('FLAG', "crew{not_the_flag}")

# Number of verification rounds
VERIFICATION_ROUNDS = 500

# Hardcoded Sudoku puzzle (0 represents empty cells)
# Impossible One
SUDOKU_PUZZLE = [
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
"""
# Possible One For Testing
SUDOKU_PUZZLE = [
    [0, 3, 4, 6, 7, 8, 9, 1, 2],
    [6, 7, 2, 1, 9, 5, 3, 4, 8],
    [1, 9, 8, 3, 4, 2, 5, 6, 7],
    [8, 5, 9, 7, 6, 1, 4, 2, 3],
    [4, 2, 6, 8, 5, 3, 7, 9, 1],
    [7, 1, 3, 9, 2, 4, 8, 5, 6],
    [9, 6, 1, 5, 3, 7, 2, 8, 4],
    [2, 8, 7, 4, 1, 9, 6, 3, 5],
    [3, 4, 5, 2, 8, 6, 1, 7, 9]
]
"""
# Dictionary to store verification session data per client
verification_sessions = {}

@app.route('/')
def index():
    return render_template('index.html', puzzle=SUDOKU_PUZZLE)

@app.route('/get_theme_color')
def get_theme_color():
    """
    Return a theme RGB color used by the UI.
    """
    rgb = random.randrange(2**32-1) // 256
    r = rgb & 0xff
    g = (rgb >> 8) & 0xff
    b = (rgb >> 16) & 0xff
    return jsonify({"r": r, "g": g, "b": b})

@socketio.on('connect')
def handle_connect():
    sid = request.sid
    join_room(sid)

@socketio.on('disconnect')
def handle_disconnect():
    # Clean up session data when client disconnects
    sid = request.sid
    if sid in verification_sessions:
        del verification_sessions[sid]

@socketio.on('start_verification')
def handle_start_verification(data):
    """Initialize a new verification process"""
    session_id = request.sid

    # Basic validation for required fields
    if not isinstance(data.get('solution', []), list):
        emit('error', {'message': 'Invalid solution format'})
        return

    verification_sessions[session_id] = {
        'current_round': 0,
        'total_rounds': VERIFICATION_ROUNDS,
        'verification_success': True,
        'solution': data.get('solution', []),
        'current_round_commitments': None,
        'current_round_challenge': None
    }

    emit('verification_started', {
        'message': 'Starting verification process...',
        'total_rounds': VERIFICATION_ROUNDS
    })

    # Request commitment for the first round
    request_commitment(session_id)

def request_commitment(session_id):
    """Request commitment for the next round from the client"""
    if session_id not in verification_sessions:
        return

    session = verification_sessions[session_id]

    if session['current_round'] >= session['total_rounds']:
        # Verification complete, send the flag
        if session['verification_success']:
            emit('verification_complete', {
                'success': True,
                'message': 'Verification successful! You can now have my contact information in the form of this flag. We must discuss further...',
                'flag': FLAG
            }, room=session_id)
        else:
            emit('verification_complete', {
                'success': False,
                'message': 'Verification failed.'
            }, room=session_id)
        return

    # Increment the round counter
    session['current_round'] += 1

    # Reset round-specific data
    session['current_round_commitments'] = None
    session['current_round_challenge'] = None

    # Request commitment
    emit('commitment_request', {
        'round': session['current_round']
    }, room=session_id)

@socketio.on('commitment_submission')
def handle_commitment_submission(data):
    """Handle the commitment submission from the client"""
    session_id = request.sid

    if session_id not in verification_sessions:
        emit('error', {'message': 'No active verification session'})
        return

    session = verification_sessions[session_id]

    # Store commitments for this round
    commitments = data.get('commitments', [])

    # Improved validation
    if not isinstance(commitments, list):
        emit('error', {'message': 'Commitments must be a list'})
        return

    if len(commitments) != 81:
        emit('error', {'message': 'Invalid number of commitments'})
        return

    # Validate each commitment is a valid 32-byte hex hash string
    for commitment in commitments:
        if (not isinstance(commitment, str)
            or len(commitment) != 64
            or not all(c in '0123456789abcdef' for c in commitment.lower())):
            emit('error', {'message': 'Invalid commitment format'})
            return

    session['current_round_commitments'] = commitments

    # Now that we have commitments, send a challenge
    # Randomly choose verification type (row, column, square, preset)
    verify_type = random.choice(['row', 'column', 'square', 'preset'])

    if verify_type == 'row':
        segment = random.randint(0, 8)  # Choose a random row (0-8)
    elif verify_type == 'column':
        segment = random.randint(0, 8)  # Choose a random column (0-8)
    elif verify_type == 'square':
        segment = random.randint(0, 8)  # Choose a random 3x3 square (0-8)
    else:  # preset
        segment = 0  # Not needed for preset

    # Store the challenge for later verification
    session['current_round_challenge'] = {
        'type': verify_type,
        'segment': segment
    }

    # Send the challenge to the client
    emit('challenge', {
        'round': session['current_round'],
        'type': verify_type,
        'segment': segment
    }, room=session_id)

@socketio.on('revelation_submission')
def handle_revelation_submission(data):
    """Handle the revelation submission from the client"""
    session_id = request.sid

    if session_id not in verification_sessions:
        emit('error', {'message': 'No active verification session'})
        return

    session = verification_sessions[session_id]

    if not session['current_round_commitments']:
        emit('error', {'message': 'No commitments received for this round'})
        return

    if not session['current_round_challenge']:
        emit('error', {'message': 'No challenge issued for this round'})
        return

    # Extract the data
    revealed = data.get('revealed', [])  # Revealed cells for this round

    # Basic validation for revealed data
    if not isinstance(revealed, list):
        emit('error', {'message': 'Revealed data must be a list'})
        return

    # Validate each revealed item has the required fields
    for item in revealed:
        if not isinstance(item, dict):
            emit('error', {'message': 'Each revealed item must be an object'})
            return

        required_fields = ['i', 'j', 'value', 'nonce']
        if not all(field in item for field in required_fields):
            emit('error', {'message': 'Missing required fields in revealed data'})
            return

        # Validate value is an integer in [1,9]
        if not isinstance(item.get('value'), int) or not (1 <= item['value'] <= 9):
            emit('error', {'message': 'Invalid value: must be integer in 1..9'})
            return

        # Validate nonce is a non-empty string
        if not isinstance(item.get('nonce'), str) or len(item['nonce']) == 0:
            emit('error', {'message': 'Invalid nonce'})
            return

        # Validate i and j are valid indices
        if not (0 <= item.get('i', -1) < 9 and 0 <= item.get('j', -1) < 9):
            emit('error', {'message': 'Invalid cell indices'})
            return

    commitments = session['current_round_commitments']
    challenge = session['current_round_challenge']

    # Verify the proof
    verification_result = verify_proof(
        challenge['type'],
        challenge['segment'],
        commitments,
        revealed,
        SUDOKU_PUZZLE
    )

    if verification_result['success']:
        # Move to the next round
        emit('verification_round_result', {
            'round': session['current_round'],
            'success': True,
            'message': f"Round {session['current_round']} verified successfully!"
        }, room=session_id)

        # Request commitment for the next round
        request_commitment(session_id)
    else:
        # Verification failed
        session['verification_success'] = False
        emit('verification_round_result', {
            'round': session['current_round'],
            'success': False,
            'message': f"Verification failed: {verification_result['message']}"
        }, room=session_id)

        # End the verification process
        emit('verification_complete', {
            'success': False,
            'message': f"Verification failed: {verification_result['message']}"
        }, room=session_id)

def verify_proof(verify_type, segment, commitments, revealed, puzzle):
    """
    Verify the submitted proof

    Args:
        verify_type: 'row', 'column', 'square', or 'preset'
        segment: Index of the segment to verify
        commitments: All hash commitments for the board
        revealed: Revealed cells (permuted values and nonces)
        puzzle: The original Sudoku puzzle

    Returns:
        Dictionary with verification result
    """
    try:
        # 1. Get the cells that should be revealed based on type and segment
        cells_to_verify = get_cells_to_verify(verify_type, segment, puzzle)

        # 2. Check if all required cells are revealed
        for cell in cells_to_verify['all']:
            i, j = cell['i'], cell['j']
            if not any(r['i'] == i and r['j'] == j for r in revealed):
                return {
                    'success': False,
                    'message': f"Cell at ({i},{j}) should have been revealed"
                }

        # 3. Verify the hashes match for revealed cells
        for rev in revealed:
            i, j = rev['i'], rev['j']
            val = rev['value']
            nonce = rev['nonce']

            # Calculate index in flattened commitments array
            flat_idx = i * 9 + j
            commitment = commitments[flat_idx]

            # Compute the hash
            computed_hash = hashlib.sha256(f"{nonce}-{val}".encode()).hexdigest()

            if computed_hash != commitment:
                return {
                    'success': False,
                    'message': f"Hash mismatch for cell ({i},{j})"
                }

        # 4. For row/column/square, verify main cells are exactly digits 1..9
        if verify_type != 'preset':
            main_values = [rev['value'] for rev in revealed
                          if any(cell['i'] == rev['i'] and cell['j'] == rev['j']
                                for cell in cells_to_verify['mainOnly'])]

            # Enforce domain and completeness
            if any(not isinstance(v, int) or v < 1 or v > 9 for v in main_values):
                return {
                    'success': False,
                    'message': "Main cell values must be integers in 1..9"
                }

            if set(main_values) != set(range(1, 10)):
                return {
                    'success': False,
                    'message': "Main cells must contain digits 1-9 exactly once"
                }

        # 5. For all types, verify the permutation is consistent for preset values
        preset_mapping = {}

        for cell in cells_to_verify['mainOnly']:
            i, j = cell['i'], cell['j']
            original_value = puzzle[i][j]

            if original_value != 0:  # If it's a preset
                for rev in revealed:
                    if rev['i'] == i and rev['j'] == j:
                        permuted_value = rev['value']

                        if original_value in preset_mapping:
                            if preset_mapping[original_value] != permuted_value:
                                return {
                                    'success': False,
                                    'message': f"Inconsistent permutation for preset value {original_value}"
                                }
                        else:
                            preset_mapping[original_value] = permuted_value

        # 6. Verify green cells have consistent permuted values
        for cell in cells_to_verify['all']:
            i, j = cell['i'], cell['j']

            # Skip main cells
            if any(c['i'] == i and c['j'] == j for c in cells_to_verify['mainOnly']):
                continue

            original_value = puzzle[i][j]

            if original_value != 0 and original_value in preset_mapping:
                expected_permuted = preset_mapping[original_value]

                for rev in revealed:
                    if rev['i'] == i and rev['j'] == j:
                        if rev['value'] != expected_permuted:
                            return {
                                'success': False,
                                'message': f"Inconsistent permutation for green cell ({i},{j})"
                            }

        return {'success': True}

    except Exception as e:
        return {
            'success': False,
            'message': f"Verification error: {str(e)}"
        }

def get_cells_to_verify(verify_type, segment, puzzle):
    """
    Determine which cells should be revealed based on the verification type

    Args:
        verify_type: 'row', 'column', 'square', or 'preset'
        segment: Index of the segment to verify
        puzzle: The original Sudoku puzzle

    Returns:
        Dictionary with keys:
        - 'all': All cells to reveal
        - 'mainOnly': Main cells (orange)
        - 'revealedPresets': Set of preset values revealed
    """
    dim = 9
    sdim = 3
    ret = []
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
        for i in range(p, p + sdim):
            for j in range(q, q + sdim):
                if puzzle[i][j] != 0:
                    revealed_presets.add(puzzle[i][j])
                main_only.append({'i': i, 'j': j})

    elif verify_type == 'preset':
        # Reveal all preset cells
        for i in range(dim):
            for j in range(dim):
                if puzzle[i][j] != 0:
                    main_only.append({'i': i, 'j': j})

    # Copy main cells to all cells
    ret = main_only.copy()

    # Add green cells (cells with values from revealed_presets)
    if verify_type != 'preset':
        for i in range(dim):
            for j in range(dim):
                # Skip if already in main cells
                if any(cell['i'] == i and cell['j'] == j for cell in main_only):
                    continue

                if puzzle[i][j] in revealed_presets:
                    ret.append({'i': i, 'j': j})

    return {
        'all': ret,
        'mainOnly': main_only,
        'revealedPresets': list(revealed_presets)
    }

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', debug=False)
