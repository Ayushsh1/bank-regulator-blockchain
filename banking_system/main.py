from __future__ import annotations

from banking_system.api import create_server


def main() -> None:
    server = create_server()
    print("Regulator banking system running on http://127.0.0.1:8080")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
