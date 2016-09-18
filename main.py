#!/usr/bin/env python3
__author__ = 'jeff'
from syndie.loader import Loader
import argparse
import logging
import os


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dir', type=str, default=os.path.join(os.environ['HOME'],'.syndie','archive'))
    ap.add_argument('--debug', action='store_true', default=True)
    ap.add_argument('--http', type=str, default="planb.i2p")

    args = ap.parse_args()
    if args.debug:
        lvl = logging.DEBUG
    else:
        lvl = logging.INFO

    logging.basicConfig(level=lvl)
    logger = logging.getLogger("main")
    logger.debug('create loader')
    loader = Loader(args.dir)
    loader.load_http('http://{}'.format(args.http))
    loader.load()



if __name__ == "__main__":
    main()
