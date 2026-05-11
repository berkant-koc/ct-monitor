"""State file round-trip: empty on missing/corrupt, persists IDs, 0600 perms."""
import json
import stat

from ct_monitor import load_state, save_state


def test_load_state_returns_empty_when_file_missing(tmp_path):
    assert load_state(tmp_path / "nope.json") == {}


def test_load_state_returns_empty_on_invalid_json(tmp_path):
    p = tmp_path / "broken.json"
    p.write_text("{not valid json")
    assert load_state(p) == {}


def test_load_state_returns_dict_from_valid_json(tmp_path):
    p = tmp_path / "state.json"
    p.write_text(json.dumps({"example.com": [1, 2, 3]}))
    assert load_state(p) == {"example.com": [1, 2, 3]}


def test_save_state_creates_parent_directory(tmp_path):
    deep = tmp_path / "a" / "b" / "c" / "state.json"
    save_state(deep, {"example.com": [42]})
    assert deep.is_file()
    assert json.loads(deep.read_text()) == {"example.com": [42]}


def test_save_state_sets_owner_only_perms(tmp_path):
    p = tmp_path / "state.json"
    save_state(p, {"example.com": [1]})
    mode = stat.S_IMODE(p.stat().st_mode)
    # Owner-rw only; group + other must have no access (file may also be 0o600 on tmpfs).
    assert mode & 0o077 == 0


def test_save_state_round_trips(tmp_path):
    p = tmp_path / "state.json"
    original = {"a.com": [1, 2], "b.com": [3, 4, 5]}
    save_state(p, original)
    assert load_state(p) == original
