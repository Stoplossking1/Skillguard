import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description='Skill Scanner API Server', formatter_class=argparse.RawDescriptionHelpFormatter, epilog='\nExamples:\n  # Start server on default port\n  skill-scanner-api\n\n  # Start on custom port\n  skill-scanner-api --port 8080\n\n  # Start with auto-reload for development\n  skill-scanner-api --reload\n\n  # Custom host and port\n  skill-scanner-api --host localhost --port 9000\n        ')
    parser.add_argument('--host', default='localhost', help='Host to bind to (default: localhost)')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to (default: 8000)')
    parser.add_argument('--reload', action='store_true', help='Enable auto-reload for development')
    args = parser.parse_args()
    try:
        import uvicorn
    except ImportError:
        print('Error: API server dependencies not installed.', file=sys.stderr)
        print('Install with: pip install fastapi uvicorn python-multipart', file=sys.stderr)
        return 1
    print('Starting Skill Scanner API Server...')
    print(f'Server: http://{args.host}:{args.port}')
    print(f'Docs: http://{args.host}:{args.port}/docs')
    print(f'Health: http://{args.host}:{args.port}/health')
    print()
    try:
        uvicorn.run('sgscanner.api.api:app', host=args.host, port=args.port, reload=args.reload)
    except KeyboardInterrupt:
        print('\nShutting down server...')
        return 0
    except Exception:
        print('Error: Could not start API server', file=sys.stderr)
        return 1
if __name__ == '__main__':
    sys.exit(main())
