import argparse
import json
import os
import sys
from dotenv import load_dotenv
from guardai.knowledge_base import ingest
from guardai.pipeline import GuardAI
from guardai.tickets import get_dashboard_stats

def cmd_check(args):
    load_dotenv()
    print("Checking environment...")
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("ERROR: GOOGLE_API_KEY is missing. Set it in your environment or local .env file.")
    else:
        print("API Key: Found")
    print("Environment check complete.")

def cmd_ingest(args):
    print("Ingesting knowledge base into ChromaDB...")
    ingest()
    print("Ingestion complete.")

def cmd_analyze(args):
    if not os.path.exists(args.file):
        print(f"Error: File '{args.file}' not found.")
        return
        
    print(f"Analyzing {args.file}...")
    with open(args.file, 'r', encoding='utf-8') as f:
        alert_text = f.read()
    
    guardai = GuardAI()
    result = guardai.analyze(alert_text, save_ticket=not args.no_save)
    
    if args.verbose:
        print("\n=== SecOps GuardAI Analysis ===")
        print(f"IoCs Detected: {json.dumps(result['iocs'], indent=2)}")
        print(f"Threat Vector: {result['classification'].threat_vector}")
        print(f"Severity:      {result['classification'].severity}")
        print(f"ATT&CK Tactics:{result['classification'].tactics}")
        print(f"Status:        {result['status']} ({result['reason']})")
        print(f"Processing Time: {result['time']:.2f} seconds")
        print("\n--- Mitigation Plan ---")
        print(result['response'])
        print("===============================\n")
    else:
        print(f"Done! Status: {result['status']} | Threat: {result['classification'].threat_vector}")

def cmd_stats(args):
    print("=== Incident Dashboard ===")
    stats_data = get_dashboard_stats()
    print(json.dumps(stats_data, indent=2))

def main():
    parser = argparse.ArgumentParser(description="SecOps GuardAI Incident Response Assistant")
    subparsers = parser.add_subparsers(dest="command")

    # Command: check
    parser_check = subparsers.add_parser("check", help="Check environment and API keys")
    parser_check.set_defaults(func=cmd_check)

    # Command: ingest
    parser_ingest = subparsers.add_parser("ingest", help="Ingest knowledge base documents")
    parser_ingest.set_defaults(func=cmd_ingest)

    # Command: analyze
    parser_analyze = subparsers.add_parser("analyze", help="Analyze a raw security alert")
    parser_analyze.add_argument("file", help="Path to the alert text file")
    parser_analyze.add_argument("--verbose", action="store_true", help="Print detailed results")
    parser_analyze.add_argument("--no-save", action="store_true", help="Do not save incident ticket")
    parser_analyze.set_defaults(func=cmd_analyze)

    # Command: stats
    parser_stats = subparsers.add_parser("stats", help="View incident summary statistics")
    parser_stats.set_defaults(func=cmd_stats)

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()