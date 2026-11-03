import argparse
import getpass
import json
import sys
from pathlib import Path

from .auth import TokenStore
from .login import browser_login
from .storage import ConnectorError, locked, read_json, write_json


def main():
    parser = argparse.ArgumentParser(description="Skolemelding native-token connector")
    parser.add_argument("--config-dir", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    login = commands.add_parser("login", help="Sign in once using ID-porten")
    method = login.add_mutually_exclusive_group()
    method.add_argument("--start", action="store_true", help="Print URL for manual callback mode")
    method.add_argument("--complete", action="store_true", help="Read callback URL without echoing")
    login.add_argument("--browser", help="Native Chromium executable (initial login only)")
    commands.add_parser("refresh", help="Force and persist one browserless token renewal")
    commands.add_parser("children", help="List authorized children locally")
    collect = commands.add_parser("collect", help="Export messages and PDF text for one child")
    collect.add_argument("--child", required=True, help="Exact username or unique first name")
    collect.add_argument("--output", type=Path, required=True)
    collect.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    store = TokenStore(args.config_dir)
    try:
        if args.command == "login":
            if args.start:
                print(store.begin_login())
                print("After signing in, run `skolemelding login --complete`.", file=sys.stderr)
                return
            if args.complete:
                store.complete_login(getpass.getpass("Paste the full app callback URL (hidden): "))
            else:
                browser_login(store, args.browser)
            print("Signed in. Native tokens saved locally; the login browser is closed.")
        elif args.command == "refresh":
            store.access_token(force=True)
            print("Native token renewal succeeded and was persisted. No browser or cookies used.")
        else:
            from .client import Client
            from .collector import collect as export_messages

            client = Client(store)
            if args.command == "children":
                print(json.dumps(client.children(), ensure_ascii=False, indent=2))
            else:
                if args.output.resolve() == args.state.resolve():
                    raise ConnectorError("Export and state paths must differ.")
                with locked(args.state.with_suffix(args.state.suffix + ".lock")):
                    previous = read_json(args.state) if args.state.exists() else None
                    output, state = export_messages(client, args.child, previous)
                    write_json(args.output, output)
                    write_json(args.state, state)
                print(json.dumps({"status": output["status"], "messages": len(output["messages"])}))
                if output["status"] != "ok":
                    return 2
        return 0
    except ConnectorError as error:
        print(f"skolemelding: {error}", file=sys.stderr)
        return 1
    except OSError:
        print(
            "skolemelding: Local I/O failed; check paths, permissions and free space.",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        print("skolemelding: Cancelled.", file=sys.stderr)
        return 1
    finally:
        store.http.close()


if __name__ == "__main__":
    sys.exit(main())
