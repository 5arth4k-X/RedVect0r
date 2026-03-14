import logging
import os
from datetime import datetime
from config import OUTPUT_DIR

os.makedirs(OUTPUT_DIR, exist_ok=True)

_log_file = os.path.join(
    OUTPUT_DIR,
    f"redvect0r_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(_log_file),
        logging.StreamHandler(),          # also echo to stdout
    ]
)

logger = logging.getLogger("RedVect0r")