import argparse
import json
from pathlib import Path
from .burp_import import load_burp
from .analyzers import analyze_many, compare
from .request_plan import plan, raw_request


def main():
    p = argparse.ArgumentParser(description='Offline PT evidence toolkit; no network requests')
    commands = p.add_subparsers(dest='command', required=True)
    scan = commands.add_parser('analyze-burp')
    scan.add_argument('xml')
    scan.add_argument('--out', required=True)
    scan.add_argument('--workers', type=int, default=4)
    scan.add_argument('--marker')
    request = commands.add_parser('plan')
    request.add_argument('url')
    request.add_argument('--out', required=True)
    request.add_argument('--raw-dir')
    diff = commands.add_parser('compare')
    diff.add_argument('xml')
    diff.add_argument('--out', required=True)
    args = p.parse_args()
    if args.command == 'analyze-burp':
        report = {'mode': 'offline', 'network_requests_sent': 0,
                  'captures': analyze_many(load_burp(args.xml), args.workers, args.marker)}
    elif args.command == 'plan':
        report = plan(args.url)
        if args.raw_dir:
            directory = Path(args.raw_dir)
            directory.mkdir(parents=True, exist_ok=True)
            for index, variant in enumerate(report['variants']):
                with (directory / f'{index:02d}_{variant["name"]}.http').open('x', newline='') as output:
                    output.write(raw_request(variant))
    else:
        captures = load_burp(args.xml)
        if len(captures) != 2:
            raise ValueError('Comparison requires exactly two captured responses')
        report = compare(*captures)
    with Path(args.out).open('x', encoding='utf-8') as output:
        json.dump(report, output, ensure_ascii=False, indent=2)
    print(args.out)


if __name__ == '__main__':
    main()
