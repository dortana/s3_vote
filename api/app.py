import sys
import os
import time
import math

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template

from crypto.encryption import EncryptionService
from crypto.pvss import PVSS
from crypto.shamir import ShamirService
from blockchain.blockchain import Blockchain
from reputation.reputation_engine import ReputationEngine
from reputation.threshold import ThresholdManager


app = Flask(__name__)

# ── Services ──────────────────────────────────────────────────────────
encryption    = EncryptionService()
shamir        = ShamirService()
rep_engine    = ReputationEngine()
threshold_mgr = ThresholdManager()
blockchain    = Blockchain()

# ── Constants ─────────────────────────────────────────────────────────
SHAMIR_N        = 6
AUTHORITY_NAMES = ['Alice', 'Bob', 'Carol', 'Dave', 'Eve', 'Frank']

# Neutral initial reputation: the value that makes threshold = base (3.0)
# with formula  threshold = 5 - 3*trust  and  trust = avg*E:
#   5 - 3*(2/3)*1 = 3  →  INITIAL_REP = 2/3
INITIAL_REP = 2 / 3

# ── Global state ──────────────────────────────────────────────────────
authorities = {name: INITIAL_REP for name in AUTHORITY_NAMES}
election    = {'status': 'idle', 'round': 0}


# ── Helpers ───────────────────────────────────────────────────────────

def compute_weights(reps):
    total = sum(reps.values())
    n     = len(reps)
    if total == 0:
        return {name: 1.0 for name in reps}
    return {name: round((rep / total) * n, 3) for name, rep in reps.items()}


def compute_threshold(reps):
    rep_list = list(reps.values())
    return threshold_mgr.adaptive_threshold(3, rep_list)


def shamir_t_from_threshold(threshold):
    """Cryptographic share count = floor(threshold), clamped to [2, SHAMIR_N]."""
    return max(2, min(SHAMIR_N, math.floor(threshold)))


def _check_impossible():
    """True when the maximum remaining valid shares can never reach shamir_t."""
    acted        = (set(election['submitted_shares']) |
                    set(election['cheaters'])         |
                    set(election['skipped']))
    still_free   = [a for a in AUTHORITY_NAMES if a not in acted]
    max_possible = len(election['submitted_shares']) + len(still_free)
    return max_possible < election['shamir_t']


def _fail_election():
    election['status'] = 'failed'
    blockchain.add_block({
        'event':           'election_failed',
        'round':           election['round'],
        'reason':          'insufficient valid shares for reconstruction',
        'valid_submitted': election['submitted_shares'],
        'cheaters':        election['cheaters'],
        'skipped':         election['skipped'],
        'shamir_t':        election['shamir_t'],
    })


def _reconstruct():
    tally = {o: 0 for o in election['options']}
    for block in blockchain.chain:
        d = block.data
        if (isinstance(d, dict)
                and d.get('event') == 'vote_cast'
                and d.get('round') == election['round']):
            try:
                plain = encryption.decrypt_vote(election['private_key'], d['encrypted_vote'])
                if plain in tally:
                    tally[plain] += 1
            except Exception:
                pass

    election['tally']  = tally
    election['status'] = 'complete'

    cw = sum(election['weights'][a] for a in election['submitted_shares'])
    blockchain.add_block({
        'event':            'reconstruction_complete',
        'round':            election['round'],
        'coalition':        election['submitted_shares'],
        'coalition_weight': round(cw, 3),
        'tally':            tally,
    })


# ── Routes ────────────────────────────────────────────────────────────

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/api/status')
def api_status():
    return jsonify({
        'system': 'S3-Vote',
        'status': 'running',
        'blocks': len(blockchain.chain),
        'round':  election.get('round', 0),
    })


@app.route('/election/create', methods=['POST'])
def create_election():
    global election

    if election.get('status') != 'idle':
        return jsonify({'error': 'An election is already in progress'}), 400

    data       = request.json
    title      = data.get('title', '').strip()
    options    = [o.strip() for o in data.get('options', []) if o.strip()]
    num_voters = int(data.get('num_voters', 0))

    if not title:
        return jsonify({'error': 'Title is required'}), 400
    if len(options) < 2:
        return jsonify({'error': 'At least 2 options are required'}), 400
    if num_voters < 1:
        return jsonify({'error': 'At least 1 voter is required'}), 400

    private_key, public_key = encryption.generate_keys()

    weights   = compute_weights(authorities)
    threshold = compute_threshold(authorities)
    shamir_t  = shamir_t_from_threshold(threshold)

    raw_shares = shamir.split_secret('S3VOTEPRIVATEKEY', threshold=shamir_t, total_shares=SHAMIR_N)

    pvss        = PVSS(p=public_key['p'], g=public_key['g'])
    commitments = pvss.batch_generate_commitments(raw_shares)

    round_num = election.get('round', 0) + 1

    election = {
        'status':           'active',
        'round':            round_num,
        'title':            title,
        'options':          options,
        'num_voters':       num_voters,
        'votes_cast':       0,
        'public_key':       public_key,
        'private_key':      private_key,
        'shares':           {AUTHORITY_NAMES[i]: raw_shares[i] for i in range(SHAMIR_N)},
        'commitments':      commitments,
        'submitted_shares': [],
        'cheaters':         [],
        'skipped':          [],
        'tally':            {},
        'weights':          weights,
        'threshold':        threshold,
        'shamir_t':         shamir_t,
        'created_at':       time.time(),
    }

    blockchain.add_block({
        'event':            'election_start',
        'round':            round_num,
        'title':            title,
        'options':          options,
        'num_voters':       num_voters,
        'threshold':        threshold,
        'pvss_commitments': [str(c)[:32] + '…' for c in commitments],
    })

    return jsonify({'status': 'ok', 'round': round_num, 'threshold': threshold, 'weights': weights})


@app.route('/election/vote', methods=['POST'])
def cast_vote():
    if election.get('status') != 'active':
        return jsonify({'error': 'No active election'}), 400

    option = request.json.get('option')

    if option not in election['options']:
        return jsonify({'error': 'Invalid option'}), 400
    if election['votes_cast'] >= election['num_voters']:
        return jsonify({'error': 'All votes already cast'}), 400

    encrypted = encryption.encrypt_vote(election['public_key'], option)
    election['votes_cast'] += 1

    blockchain.add_block({
        'event':          'vote_cast',
        'round':          election['round'],
        'encrypted_vote': encrypted,
    })

    if election['votes_cast'] >= election['num_voters']:
        election['status'] = 'reconstruction'
        blockchain.add_block({
            'event':      'voting_closed',
            'round':      election['round'],
            'votes_cast': election['votes_cast'],
        })

    return jsonify({
        'votes_cast': election['votes_cast'],
        'phase':      election['status'],
    })


@app.route('/election/end', methods=['POST'])
def end_voting():
    if election.get('status') != 'active':
        return jsonify({'error': 'No active voting phase'}), 400

    election['status'] = 'reconstruction'
    blockchain.add_block({
        'event':      'voting_closed',
        'round':      election['round'],
        'votes_cast': election['votes_cast'],
    })
    return jsonify({'status': 'ok'})


@app.route('/election/submit-share', methods=['POST'])
def submit_share():
    if election.get('status') != 'reconstruction':
        return jsonify({'error': 'Not in reconstruction phase'}), 400

    authority = request.json.get('authority')
    tampered  = bool(request.json.get('tampered', False))
    skip      = bool(request.json.get('skip', False))

    if authority not in election['shares']:
        return jsonify({'error': 'Unknown authority'}), 400
    already_acted = (authority in election['submitted_shares']
                     or authority in election['cheaters']
                     or authority in election['skipped'])
    if already_acted:
        return jsonify({'error': 'Share already submitted'}), 400

    if skip:
        election['skipped'].append(authority)
        blockchain.add_block({
            'event':     'share_skipped',
            'round':     election['round'],
            'authority': authority,
        })
        election_failed = _check_impossible()
        if election_failed:
            _fail_election()
        return jsonify({
            'skipped':          True,
            'authority':        authority,
            'submitted':        election['submitted_shares'],
            'cheaters':         election['cheaters'],
            'skipped_list':     election['skipped'],
            'coalition_weight': round(sum(election['weights'][a] for a in election['submitted_shares']), 3),
            'threshold':        election['threshold'],
            'reconstructed':    False,
            'election_failed':  election_failed,
        })

    idx        = AUTHORITY_NAMES.index(authority)
    real_share = election['shares'][authority]
    commitment = election['commitments'][idx]

    submitted_share = (real_share + '_TAMPERED') if tampered else real_share

    pvss     = PVSS(p=election['public_key']['p'], g=election['public_key']['g'])
    verified = pvss.verify_share(submitted_share, commitment)

    if not verified:
        election['cheaters'].append(authority)
        blockchain.add_block({
            'event':     'share_invalid',
            'round':     election['round'],
            'authority': authority,
        })
        election_failed = _check_impossible()
        if election_failed:
            _fail_election()
        return jsonify({
            'verified':         False,
            'cheater':          authority,
            'submitted':        election['submitted_shares'],
            'cheaters':         election['cheaters'],
            'skipped_list':     election['skipped'],
            'coalition_weight': round(sum(election['weights'][a] for a in election['submitted_shares']), 3),
            'threshold':        election['threshold'],
            'reconstructed':    False,
            'election_failed':  election_failed,
        })

    election['submitted_shares'].append(authority)
    cw = sum(election['weights'][a] for a in election['submitted_shares'])

    blockchain.add_block({
        'event':            'share_submitted',
        'round':            election['round'],
        'authority':        authority,
        'coalition_weight': round(cw, 3),
    })

    can_reconstruct = (
        len(election['submitted_shares']) >= election['shamir_t']
        and cw >= election['threshold']
    )

    if can_reconstruct:
        _reconstruct()

    return jsonify({
        'verified':         True,
        'submitted':        election['submitted_shares'],
        'cheaters':         election['cheaters'],
        'skipped_list':     election['skipped'],
        'coalition_weight': round(cw, 3),
        'threshold':        election['threshold'],
        'reconstructed':    election['status'] == 'complete',
    })


@app.route('/election/apply-failure', methods=['POST'])
def apply_failure():
    if election.get('status') != 'failed':
        return jsonify({'error': 'Election has not failed'}), 400

    shamir_t  = election['shamir_t']
    threshold = election['threshold']
    weights   = election['weights']
    avg_needed = threshold / shamir_t if shamir_t > 0 else 1.0

    for name in AUTHORITY_NAMES:
        submitted = name in election['submitted_shares']
        cheated   = name in election['cheaters']

        P = 1.0 if submitted else (0.5 if cheated else 0.0)
        C = min(1.0, weights[name] / avg_needed) if submitted else 0.0
        H = 1.0 if submitted else (0.0 if cheated else 0.5)

        authorities[name] = rep_engine.update_reputation(
            authorities[name],
            participation=P, contribution=C, honesty=H,
        )

    new_weights   = compute_weights(authorities)
    new_threshold = compute_threshold(authorities)

    blockchain.add_block({
        'event':         'reputation_update',
        'round':         election['round'],
        'reputations':   {k: round(v, 3) for k, v in authorities.items()},
        'new_threshold': new_threshold,
    })

    election['status'] = 'idle'

    return jsonify({
        'reputations':    {k: round(v, 4) for k, v in authorities.items()},
        'weights':        new_weights,
        'next_threshold': new_threshold,
    })


@app.route('/election/update-reputations', methods=['POST'])
def update_reputations():
    if election.get('status') != 'complete':
        return jsonify({'error': 'Election not complete'}), 400

    updates = request.json
    for name, scores in updates.items():
        if name in authorities:
            authorities[name] = rep_engine.update_reputation(
                authorities[name],
                participation=float(scores.get('participation', 0.5)),
                contribution=float(scores.get('contribution', 0.5)),
                honesty=float(scores.get('honesty', 0.5)),
            )

    new_weights   = compute_weights(authorities)
    new_threshold = compute_threshold(authorities)

    blockchain.add_block({
        'event':         'reputation_update',
        'round':         election['round'],
        'reputations':   {k: round(v, 3) for k, v in authorities.items()},
        'new_threshold': new_threshold,
    })

    election['status'] = 'idle'

    return jsonify({
        'reputations':    {k: round(v, 4) for k, v in authorities.items()},
        'weights':        new_weights,
        'next_threshold': new_threshold,
    })


@app.route('/election/state')
def election_state():
    w         = election.get('weights', compute_weights(authorities))
    submitted = election.get('submitted_shares', [])
    cw        = round(sum(w.get(a, 0) for a in submitted), 3)

    return jsonify({
        'status':           election.get('status', 'idle'),
        'round':            election.get('round', 0),
        'title':            election.get('title'),
        'options':          election.get('options', []),
        'num_voters':       election.get('num_voters', 0),
        'votes_cast':       election.get('votes_cast', 0),
        'threshold':        election.get('threshold', compute_threshold(authorities)),
        'shamir_t':         election.get('shamir_t', shamir_t_from_threshold(compute_threshold(authorities))),
        'weights':          w,
        'submitted_shares': submitted,
        'cheaters':         election.get('cheaters', []),
        'skipped':          election.get('skipped', []),
        'coalition_weight': cw,
        'tally':            election.get('tally', {}),
    })


@app.route('/authorities')
def get_authorities():
    weights = compute_weights(authorities)
    return jsonify([
        {'name': name, 'reputation': round(rep, 4), 'weight': weights[name]}
        for name, rep in authorities.items()
    ])


@app.route('/chain')
def get_chain():
    return jsonify([
        {'index': b.index, 'timestamp': b.timestamp, 'data': b.data, 'hash': b.hash}
        for b in blockchain.chain
    ])


if __name__ == '__main__':
    app.run(debug=True, port=8080)
