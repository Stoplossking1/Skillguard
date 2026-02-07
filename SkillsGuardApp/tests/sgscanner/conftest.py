from pathlib import Path
from dotenv import load_dotenv
project_root = Path(__file__).parent.parent
env_file = project_root / '.env'
if env_file.exists():
    load_dotenv(env_file)
    print(f'[OK] Loaded environment variables from {env_file}')
else:
    print(f'[WARNING] No .env file found at {env_file}')
