from pathlib import Path
from nettwin.core import load,verify,decide,Flow,to_dict,from_dict
from nettwin.mutation import benchmark
from nettwin.diagnosis import diagnose,repair
ROOT=Path(__file__).resolve().parents[1]
def reference():return load(str(ROOT/'benchmarks/guest_isolation.json'))
def faulty():return load(str(ROOT/'benchmarks/faulty_guest_isolation.json'))
def test_reference():
 s=reference();assert verify(s)['all_passed'];assert verify(s)['total']==5
 assert from_dict(to_dict(s))==s
def test_fault_detection():
 r=verify(faulty());assert r['passed']==3;assert not r['all_passed']
def test_mutations():
 b=benchmark(reference());assert b['mutants']>0;assert b['confirmed_faults']>0
 assert b['detected_confirmed']==b['confirmed_faults']
def test_diagnosis():
 d=diagnose(faulty());assert len(d['failures'])==2
 assert any(x['rule_id']=='bad_guest_allow' for x in d['candidates'])
def test_repair():
 r=repair(faulty());assert r['success'];assert verify(r['scenario'])['all_passed']
def test_first_match():
 s=faulty();assert decide(s,Flow('guest','database','tcp',5432))[0]=='ALLOW'
