import secure_record as sr


def test_ctr_counter_overlap_for_multi_block_records():
    key = bytes(32)
    session_id = bytes(8)
    long_stream = sr.aes_ctr(key, sr.make_iv(session_id, 0), bytes(32))
    next_record_stream = sr.aes_ctr(key, sr.make_iv(session_id, 1), bytes(16))
    assert long_stream[16:32] == next_record_stream
