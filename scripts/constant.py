import logging
from pathlib import Path

ROOT_PATH = Path(__file__).parent.parent
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
