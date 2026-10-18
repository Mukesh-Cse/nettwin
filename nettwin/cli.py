import argparse,json
from pathlib import Path
from .core import load,to_dict,verify
from .mutation import benchmark
from .diagnosis import diagnose,repair
from .experiments import compare

def main():
    parser=argparse.ArgumentParser(description="NetTwin policy verification lab")
    parser.add_argument('command',choices=['verify','mutate','diagnose','repair','experiment'])
    parser.add_argument('--scenario',default=str(Path(__file__).resolve().parent.parent/'benchmarks'/'guest_isolation.json'))
    parser.add_argument('--output',help='Save JSON result')
    args=parser.parse_args();s=load(args.scenario)
    if args.command=='verify': result=verify(s)
    elif args.command=='mutate':result=benchmark(s)
    elif args.command=='diagnose':result=diagnose(s)
    elif args.command=='experiment':result=compare(s)
    else:
        fixed=repair(s);result={"success":fixed['success'],"change":fixed['change'],
                               "verification":verify(fixed['scenario']),"configuration":to_dict(fixed['scenario'])}
    output=json.dumps(result,indent=2)
    if args.output: Path(args.output).write_text(output,encoding='utf8')
    print(output)
if __name__=='__main__':main()
