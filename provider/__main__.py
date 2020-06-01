import argparse
import sys

from provider import app


parser = argparse.ArgumentParser(description='Flask commandline options')
parser.add_argument('--config', type=str, default='provider/config.yml')
args = parser.parse_args()


if __name__ == "__main__":
    sys.exit(app.main(args.config))
