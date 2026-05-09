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

# ── Neutral initial reputation ────────────────────────────────────────
# trust = avg * E = (2/3) * 1 = 2/3  →  threshold = 5 - 3*(2/3) = 3.0
INITIAL_REP = 2 / 3

# ── Persistent reputation registry (survives across elections) ────────
# Maps authority name → reputation score.
# New authorities start at INITIAL_REP; history accumulates over rounds.
reputation_registry = {}

# ── Global election state ─────────────────────────────────────────────
election = {'status': 'idle', 'round': 0}


# ── Helpers ───────────────────────────────────────────────────────────

def compute_weights(reps):
    total = sum(reps.values())
    n     = len(reps)
    if total == 0:
        return {name: 1.0 for name in reps}
    return {name: round((rep / total) * n, 3) for name, rep in reps.items()}


def compute_threshold(reps):
    return threshold_mgr.adaptive_threshold(list(reps.values()))


def shamir_t_from_threshold(threshold, n):
    """Fallback: derive shamir_t from threshold if not provided by admin."""
    return max(2, min(n, math.floor(threshold)))


def _check_impossible():
    """True when reconstruction can never be completed."""
    acted      = (set(election['submitted_shares']) |
                  set(election['cheaters'])         |
                  set(election['skipped']))
    still_free = [a for a in election['authority_names'] if a not in acted]

    max_shares = len(election['submitted_shares']) + len(still_free)
    if max_shares < election['shamir_t']:
        return True

    # Also impossible if even adding all remaining free shares can't reach weight threshold
    current_weight  = sum(election['weights'][a] for a in election['submitted_shares'])
    max_free_weight = sum(election['weights'][a] for a in still_free)
    if current_weight + max_free_weight < election['threshold']:
        return True

    return False


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


def _save_reputations_to_registry():
    """Persist updated auth_reps back into the global registry."""
    for name, rep in election.get('auth_reps', {}).items():
        reputation_registry[name] = rep


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

    data            = request.json
    title           = data.get('title', '').strip()
    options         = [o.strip() for o in data.get('options', []) if o.strip()]
    num_voters      = int(data.get('num_voters', 0))
    authority_names = [a.strip() for a in data.get('authorities', []) if a.strip()]

    if not title:
        return jsonify({'error': 'Title is required'}), 400
    if len(options) < 2:
        return jsonify({'error': 'At least 2 options are required'}), 400
    if num_voters < 1:
        return jsonify({'error': 'At least 1 voter is required'}), 400
    if len(authority_names) < 3:
        return jsonify({'error': 'At least 3 authorities are required'}), 400
    if len(authority_names) != len(set(authority_names)):
        return jsonify({'error': 'Duplicate authority names are not allowed'}), 400

    n = len(authority_names)

    # shamir_t: admin-defined cryptographic minimum, must be in [2, n]
    raw_shamir_t = data.get('shamir_t')
    if raw_shamir_t is not None:
        raw_shamir_t = int(raw_shamir_t)
        if raw_shamir_t < 2:
            return jsonify({'error': 'Min shares must be at least 2 — a (1,n) scheme offers no security'}), 400
        if raw_shamir_t > n:
            return jsonify({'error': f'Min shares ({raw_shamir_t}) cannot exceed the number of authorities ({n})'}), 400
        shamir_t = raw_shamir_t
    else:
        shamir_t = None  # computed after threshold below

    # Load reputations from registry; new authorities start at INITIAL_REP
    auth_reps = {name: reputation_registry.get(name, INITIAL_REP) for name in authority_names}

    private_key, public_key = encryption.generate_keys()

    weights   = compute_weights(auth_reps)
    threshold = compute_threshold(auth_reps)

    if shamir_t is None:
        shamir_t = shamir_t_from_threshold(threshold, n)

    raw_shares  = shamir.split_secret('S3VOTEPRIVATEKEY', threshold=shamir_t, total_shares=n)
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
        'authority_names':  authority_names,
        'shamir_n':         n,
        'auth_reps':        auth_reps,
        'shares':           {authority_names[i]: raw_shares[i] for i in range(n)},
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
        'authorities':      authority_names,
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

    return jsonify({'votes_cast': election['votes_cast'], 'phase': election['status']})


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
    if (authority in election['submitted_shares']
            or authority in election['cheaters']
            or authority in election['skipped']):
        return jsonify({'error': 'Share already submitted'}), 400

    def _base_response(extra={}):
        cw = round(sum(election['weights'][a] for a in election['submitted_shares']), 3)
        return {
            'submitted':        election['submitted_shares'],
            'cheaters':         election['cheaters'],
            'skipped_list':     election['skipped'],
            'coalition_weight': cw,
            'threshold':        election['threshold'],
            'reconstructed':    election['status'] == 'complete',
            **extra,
        }

    if skip:
        election['skipped'].append(authority)
        blockchain.add_block({'event': 'share_skipped', 'round': election['round'], 'authority': authority})
        failed = _check_impossible()
        if failed:
            _fail_election()
        return jsonify(_base_response({'skipped': True, 'authority': authority, 'election_failed': failed}))

    idx             = election['authority_names'].index(authority)
    real_share      = election['shares'][authority]
    commitment      = election['commitments'][idx]
    submitted_share = (real_share + '_TAMPERED') if tampered else real_share

    pvss     = PVSS(p=election['public_key']['p'], g=election['public_key']['g'])
    verified = pvss.verify_share(submitted_share, commitment)

    if not verified:
        election['cheaters'].append(authority)
        blockchain.add_block({'event': 'share_invalid', 'round': election['round'], 'authority': authority})
        failed = _check_impossible()
        if failed:
            _fail_election()
        return jsonify(_base_response({'verified': False, 'cheater': authority, 'election_failed': failed}))

    election['submitted_shares'].append(authority)
    cw = sum(election['weights'][a] for a in election['submitted_shares'])
    blockchain.add_block({
        'event':            'share_submitted',
        'round':            election['round'],
        'authority':        authority,
        'coalition_weight': round(cw, 3),
    })

    if len(election['submitted_shares']) >= election['shamir_t'] and cw >= election['threshold']:
        _reconstruct()

    return jsonify(_base_response({'verified': True}))


def _apply_rep_updates(scores_by_name):
    """Update auth_reps from a {name: {P,C,H}} dict, save to registry."""
    auth_reps  = election['auth_reps']
    weights    = election['weights']
    shamir_t   = election['shamir_t']
    threshold  = election['threshold']
    avg_needed = threshold / shamir_t if shamir_t > 0 else 1.0

    for name in election['authority_names']:
        submitted = name in election['submitted_shares']
        cheated   = name in election['cheaters']

        if scores_by_name:
            s = scores_by_name.get(name, {})
            P = float(s.get('participation', 0.5))
            C = float(s.get('contribution',  0.5))
            H = float(s.get('honesty',       0.5))
        else:
            P = 1.0 if submitted else (0.5 if cheated else 0.0)
            C = min(1.0, weights.get(name, 0) / avg_needed) if submitted else 0.0
            H = 1.0 if submitted else (0.0 if cheated else 0.5)

        auth_reps[name] = rep_engine.update_reputation(
            auth_reps[name], participation=P, contribution=C, honesty=H,
        )

    _save_reputations_to_registry()

    new_weights   = compute_weights(reputation_registry)
    new_threshold = compute_threshold(reputation_registry)

    blockchain.add_block({
        'event':         'reputation_update',
        'round':         election['round'],
        'reputations':   {k: round(v, 3) for k, v in reputation_registry.items()},
        'new_threshold': new_threshold,
    })

    election['status'] = 'idle'
    return new_weights, new_threshold


@app.route('/election/update-reputations', methods=['POST'])
def update_reputations():
    if election.get('status') != 'complete':
        return jsonify({'error': 'Election not complete'}), 400

    new_weights, new_threshold = _apply_rep_updates(request.json)
    return jsonify({
        'reputations':    {k: round(v, 4) for k, v in reputation_registry.items()},
        'weights':        new_weights,
        'next_threshold': new_threshold,
    })


@app.route('/election/apply-failure', methods=['POST'])
def apply_failure():
    if election.get('status') != 'failed':
        return jsonify({'error': 'Election has not failed'}), 400

    new_weights, new_threshold = _apply_rep_updates(None)
    return jsonify({
        'reputations':    {k: round(v, 4) for k, v in reputation_registry.items()},
        'weights':        new_weights,
        'next_threshold': new_threshold,
    })


@app.route('/election/state')
def election_state():
    w         = election.get('weights', {})
    submitted = election.get('submitted_shares', [])
    cw        = round(sum(w.get(a, 0) for a in submitted), 3)

    if election.get('status', 'idle') == 'idle':
        reps      = reputation_registry
        w         = compute_weights(reps) if reps else {}
        threshold = compute_threshold(reps) if reps else 3.0
        n         = len(reps)
        shamir_t  = shamir_t_from_threshold(threshold, n) if n >= 3 else 3
    else:
        threshold = election.get('threshold', 3.0)
        shamir_t  = election.get('shamir_t', 3)
        n         = election.get('shamir_n', len(w))

    return jsonify({
        'status':           election.get('status', 'idle'),
        'round':            election.get('round', 0),
        'title':            election.get('title'),
        'options':          election.get('options', []),
        'num_voters':       election.get('num_voters', 0),
        'votes_cast':       election.get('votes_cast', 0),
        'threshold':        threshold,
        'shamir_t':         shamir_t,
        'shamir_n':         n,
        'weights':          w,
        'authority_names':  election.get('authority_names', []),
        'submitted_shares': submitted,
        'cheaters':         election.get('cheaters', []),
        'skipped':          election.get('skipped', []),
        'coalition_weight': cw,
        'tally':            election.get('tally', {}),
    })


@app.route('/authorities')
def get_authorities():
    if election.get('status') != 'idle':
        reps    = election.get('auth_reps', {})
        weights = election.get('weights', compute_weights(reps))
    else:
        reps    = reputation_registry
        weights = compute_weights(reps) if reps else {}
    return jsonify([
        {'name': name, 'reputation': round(rep, 4), 'weight': weights.get(name, 1.0),
         'is_new': name not in reputation_registry}
        for name, rep in reps.items()
    ])


@app.route('/registry')
def get_registry():
    if not reputation_registry:
        return jsonify([])
    weights = compute_weights(reputation_registry)
    return jsonify([
        {'name': name, 'reputation': round(rep, 4), 'weight': round(weights.get(name, 1.0), 3)}
        for name, rep in reputation_registry.items()
    ])


@app.route('/chain')
def get_chain():
    return jsonify([
        {'index': b.index, 'timestamp': b.timestamp, 'data': b.data, 'hash': b.hash}
        for b in blockchain.chain
    ])


if __name__ == '__main__':
    app.run(debug=True, port=8080)
